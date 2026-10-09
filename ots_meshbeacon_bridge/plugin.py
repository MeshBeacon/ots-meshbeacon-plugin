from __future__ import annotations

import datetime as dt
import json
import os
import re
import socket
import threading
import traceback
import uuid
from importlib import metadata as importlib_metadata
from xml.etree.ElementTree import Element, SubElement, fromstring, tostring

import paho.mqtt.client as mqtt
import pika
import sqlalchemy.exc
from flask import Flask

from opentakserver.plugins.Plugin import Plugin

from .blueprint import build_blueprint
from .crypto import OpenTakCrypto

UNKNOWN = "9999999.0"


class MeshBeaconPlugin(Plugin):
    """
    Bridges MeshBeacon (https://github.com/MeshBeacon/meshbeacon) telemetry
    into OpenTAKServer over an encrypted MQTT link, and relays operator
    commands back to the mesh. See this package's README.md for setup and
    the crypto design shared with MeshBeacon's OpenTakCryptoService.
    """

    def __init__(self) -> None:
        super().__init__()
        self.name = "MeshBeacon Bridge"
        self.distro = "ots-meshbeacon-bridge"

        self._crypto: OpenTakCrypto | None = None
        self._mqtt_client: mqtt.Client | None = None
        self._cot_socket: socket.socket | None = None
        self._cot_target: tuple[str, int] = ("127.0.0.1", 8088)
        self._event_topic = "hub/opentak/event"
        self._command_topic = "hub/opentak/command"
        self._lock = threading.Lock()
        self._connected = False

        # Relays GeoChat replies typed in ATAK/WinTAK/iTAK back to the mesh.
        # OTS's own cot_parser only relays outgoing GeoChat to Meshtastic
        # (hardcoded, gated by OTS_ENABLE_MESHTASTIC) -- there's no generic
        # plugin hook for other bridges, so this plugin binds its own queue
        # to OTS's "cot_parser" direct exchange to get a copy of every parsed
        # CoT event (same envelope EudHandler/meshtastic_controller publish:
        # {"uid":..., "cot": "<event .../>"}) alongside cot_parser's own
        # queue, without needing any change to OTS core.
        self._geochat_thread: threading.Thread | None = None
        self._geochat_stop = threading.Event()
        self._geochat_connection: pika.BlockingConnection | None = None

    def load_metadata(self) -> dict:
        # Pull real package metadata when available (e.g. author, license,
        # Project-URL entries) so the OTS UI's plugin "About" tab has
        # everything it expects. Every key the UI reads must still be
        # present -- even as an empty value -- or its unguarded
        # `about.project_url.forEach(...)` (etc.) throws and blanks the
        # whole page, since optional chaining only protects the `about?.`
        # access, not the rest of the chain.
        try:
            meta = importlib_metadata.metadata(self.distro).json
        except importlib_metadata.PackageNotFoundError:
            meta = {}

        self.metadata = {
            "name": self.name,
            "distro": self.distro,
            "version": meta.get("version", "1.0.0"),
            "author": meta.get("author", "OpenTAKServer"),
            "author_email": meta.get("author_email", "zaihan@meshbeacon.org"),
            "summary": meta.get("summary", ""),
            "description": meta.get("description", ""),
            "description_content_type": meta.get("description_content_type", "text/markdown"),
            "license": meta.get("license", ""),
            "classifier": meta.get("classifier", []),
            "requires_dist": meta.get("requires_dist", []),
            "requires_python": meta.get("requires_python", ""),
            "metadata_version": meta.get("metadata_version", "2.1"),
            "project_url": meta.get("project_url", []),
        }
        return self.metadata

    def get_info(self) -> dict | None:
        return {
            "name": self.name,
            "distro": self.distro,
            "public_key": os.getenv("OTS_MESHBEACON_PUBLIC_KEY", ""),
            "event_topic": self._event_topic,
            "command_topic": self._command_topic,
            "configured": bool(self._crypto and self._crypto.is_configured()),
            "connected": self._connected,
        }

    def activate(self, app: Flask, enabled: bool) -> None:
        from opentakserver.extensions import logger

        self._logger = logger
        self._app = app

        if not enabled:
            logger.info("MeshBeacon plugin: disabled, not starting MQTT client")
            return

        private_key = os.getenv("OTS_MESHBEACON_PRIVATE_KEY", "")
        public_key = os.getenv("OTS_MESHBEACON_PUBLIC_KEY", "")
        peer_public_key = os.getenv("OTS_MESHBEACON_PEER_PUBLIC_KEY", "")
        self._crypto = OpenTakCrypto(private_key, public_key, peer_public_key)

        if not self._crypto.is_configured():
            logger.warning(
                "MeshBeacon plugin: keypair not fully configured (OTS_MESHBEACON_PRIVATE_KEY, "
                "OTS_MESHBEACON_PUBLIC_KEY, OTS_MESHBEACON_PEER_PUBLIC_KEY are all required), "
                "staying inert. Run 'python -m ots_meshbeacon_bridge.keygen' to generate a keypair."
            )
            return

        self._event_topic = os.getenv("OTS_MESHBEACON_EVENT_TOPIC", self._event_topic)
        self._command_topic = os.getenv("OTS_MESHBEACON_COMMAND_TOPIC", self._command_topic)
        # This plugin runs in-process with OTS and always talks to
        # eud_handler's plain TCP listener over loopback, so this must NOT
        # default to OTS_LISTENER_ADDRESS -- that's a *bind* address (commonly
        # "0.0.0.0" so eud_handler/nginx/etc. accept connections on every
        # interface) and isn't a valid, portable *destination* to connect() to.
        # An explicit OTS_MESHBEACON_COT_TARGET_HOST is only needed if
        # eud_handler's TCP listener runs in a different container/host.
        #
        # NOTE: eud_handler's --udp mode is broken in this OTS version --
        # EudHandler.handle() unconditionally calls self.request.recv(),
        # but socketserver's UDP request objects are a (data, socket) tuple,
        # not a connected socket, so every UDP datagram crashes the handler
        # with "'tuple' object has no attribute 'recv'" before it ever
        # reaches handle_cot()/publish_cot(). Plain TCP (EudServer, port
        # OTS_TCP_STREAMING_PORT/8088) uses a real connected socket and
        # works correctly, so this plugin speaks CoT-over-TCP instead.
        self._cot_target = (
            os.getenv("OTS_MESHBEACON_COT_TARGET_HOST", "127.0.0.1"),
            int(app.config.get("OTS_TCP_STREAMING_PORT", 8088)),
        )
        self._cot_socket = None

        host = os.getenv("OTS_MESHBEACON_MQTT_HOST", "127.0.0.1")
        port = int(os.getenv("OTS_MESHBEACON_MQTT_PORT", "1883"))
        username = os.getenv("OTS_MESHBEACON_MQTT_USERNAME")
        password = os.getenv("OTS_MESHBEACON_MQTT_PASSWORD")

        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
            client_id="ots-meshbeacon-bridge",
            protocol=mqtt.MQTTv311,
        )
        if username:
            client.username_pw_set(username, password)
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.on_disconnect = self._on_disconnect
        self._mqtt_client = client

        self.blueprint = build_blueprint(self)

        try:
            client.connect_async(host, port, keepalive=30)
            client.loop_start()
            logger.info(f"MeshBeacon plugin: connecting to MQTT broker {host}:{port}")
        except BaseException as e:
            logger.error(f"MeshBeacon plugin: failed to connect to MQTT broker {host}:{port}: {e}")
            logger.debug(traceback.format_exc())

        self._geochat_stop.clear()
        self._geochat_thread = threading.Thread(
            target=self._geochat_listener_loop, name="meshbeacon-geochat-listener", daemon=True
        )
        self._geochat_thread.start()

    def stop(self) -> None:
        self._geochat_stop.set()
        if self._geochat_connection is not None:
            try:
                self._geochat_connection.close()
            except BaseException:
                pass
        if self._geochat_thread is not None:
            self._geochat_thread.join(timeout=5)
            self._geochat_thread = None

        if self._mqtt_client is not None:
            try:
                self._mqtt_client.loop_stop()
                self._mqtt_client.disconnect()
            except BaseException:
                pass
            self._mqtt_client = None

        if self._cot_socket is not None:
            try:
                self._cot_socket.close()
            except OSError:
                pass
            self._cot_socket = None

        self._connected = False

    # -- MQTT callbacks -----------------------------------------------------

    def _on_connect(self, client, userdata, flags, rc) -> None:
        if rc == 0:
            self._connected = True
            client.subscribe(self._event_topic, qos=0)
            self._logger.info(f"MeshBeacon plugin: connected, subscribed to {self._event_topic}")
        else:
            self._logger.error(f"MeshBeacon plugin: MQTT connect failed, rc={rc}")

    def _on_disconnect(self, client, userdata, rc) -> None:
        self._connected = False
        self._logger.warning(f"MeshBeacon plugin: MQTT disconnected, rc={rc}")

    # -- ATAK/WinTAK/iTAK GeoChat -> MeshBeacon command ----------------------

    def _geochat_listener_loop(self) -> None:
        """
        Reconnects with backoff for as long as the plugin is active. A
        single dropped connection (broker restart, network blip, etc.)
        would otherwise silently and permanently stop GeoChat replies from
        ever reaching the mesh again until OTS itself was restarted.
        """
        while not self._geochat_stop.is_set():
            try:
                self._consume_geochat_once()
            except BaseException as e:
                if self._geochat_stop.is_set():
                    break
                self._logger.warning(f"MeshBeacon plugin: GeoChat listener error, retrying: {e}")
                self._logger.debug(traceback.format_exc())
            self._geochat_stop.wait(5)

    def _consume_geochat_once(self) -> None:
        """
        Binds a queue of our own to OTS's existing "cot_parser" direct
        exchange (routing key "cot_parser"), the same exchange EudHandler
        and the Meshtastic controller publish every parsed CoT event to.
        Because it's a *direct* exchange, a second queue bound with the
        same routing key gets its own copy of every message -- this runs
        entirely alongside OTS's own cot_parser consumer without needing
        any change to OTS core, which has no generic "outgoing GeoChat"
        hook for third-party bridges (only Meshtastic is wired in,
        hardcoded in cot_parser.parse_geochat()).
        """
        host = self._app.config.get("OTS_RABBITMQ_SERVER_ADDRESS", "127.0.0.1")
        username = self._app.config.get("OTS_RABBITMQ_USERNAME", "guest")
        password = self._app.config.get("OTS_RABBITMQ_PASSWORD", "guest")

        credentials = pika.PlainCredentials(username, password)
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(host=host, credentials=credentials)
        )
        self._geochat_connection = connection
        channel = connection.channel()
        channel.exchange_declare("cot_parser", durable=True, exchange_type="direct")
        channel.queue_declare(queue="meshbeacon_bridge_geochat", auto_delete=True)
        channel.queue_bind(
            exchange="cot_parser", queue="meshbeacon_bridge_geochat", routing_key="cot_parser"
        )
        channel.basic_consume(
            queue="meshbeacon_bridge_geochat",
            on_message_callback=self._on_geochat_message,
            auto_ack=True,
        )
        self._logger.info("MeshBeacon plugin: listening for GeoChat replies to relay to the mesh")
        try:
            channel.start_consuming()
        finally:
            self._geochat_connection = None

    def _on_geochat_message(self, channel, method, properties, body: bytes) -> None:
        try:
            envelope = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return

        cot_xml = envelope.get("cot")
        if not cot_xml:
            # Disconnect notifications and other non-CoT envelopes carry no
            # "cot" payload -- nothing to parse.
            return

        try:
            event = fromstring(cot_xml)
        except BaseException:
            return

        if event.get("type") != "b-t-f":
            # Not a GeoChat event (position update, alert, etc.)
            return

        detail = event.find("detail")
        if detail is None:
            return
        # <chatgrp> is nested inside <__chat>, not a direct child of
        # <detail> (see this file's own _build_geochat_cot() for the same
        # shape) -- ElementTree's find() only matches immediate children
        # for a plain tag name, so a plain detail.find("chatgrp") always
        # returns None and silently drops every real GeoChat CoT. ".//"
        # searches all descendants instead.
        chatgrp = detail.find(".//chatgrp")
        remarks = detail.find("remarks")
        if chatgrp is None or remarks is None or not remarks.text:
            return

        sender_uid = chatgrp.get("uid0", "")
        if sender_uid.startswith("meshbeacon-"):
            # Echo of a chat message this plugin itself already relayed
            # from MeshBeacon into OTS (_build_geochat_cot) -- ignore, or
            # every Duck message would immediately bounce back to itself.
            return

        # A 1:1 DM's chatgrp carries the recipient's uid in a "uidN"
        # attribute (N >= 1); broadcasts to "All Chat Rooms" don't name any
        # specific EUD here, so under normal circumstances they're not
        # relayed -- only replies addressed to a specific Duck's contact
        # are. In practice though, iTAK is known to never actually transmit
        # a private 1:1 GeoChat CoT at all (the message only ever appears
        # in iTAK's own local chat UI, never reaching the server), while
        # broadcasts to "All Chat Rooms" do transmit reliably. As a
        # fallback for iTAK operators, a broadcast message starting with
        # "@<duck_id>" is therefore also treated as a directed reply.
        for attr, uid in chatgrp.attrib.items():
            if not attr.startswith("uid") or attr == "uid0":
                continue
            if not uid.startswith("meshbeacon-"):
                continue

            duck_id = uid[len("meshbeacon-") :]
            self._relay_geochat_reply(duck_id, remarks.text)
            return

        mention = re.match(r"^\s*@(\S+)[:,]?\s+(.+)$", remarks.text, re.DOTALL)
        if mention:
            duck_id = self._resolve_mentioned_duck(mention.group(1))
            if duck_id is not None:
                self._relay_geochat_reply(duck_id, mention.group(2))

    def _resolve_mentioned_duck(self, candidate: str) -> str | None:
        """
        Case-insensitively resolves an "@name" mention typed in a broadcast
        GeoChat to the exact duck_id this plugin registered the Duck's EUD
        under, or None if no registered Duck matches. Avoids silently
        relaying commands to a typo'd or nonexistent duck_id.
        """
        from opentakserver.extensions import db
        from opentakserver.models.EUD import EUD

        wanted = f"meshbeacon-{candidate}".lower()
        with self._app.app_context():
            euds = db.session.execute(
                db.session.query(EUD).filter(EUD.uid.like("meshbeacon-%"))
            ).all()
            for row in euds:
                eud = row[0]
                if eud.uid.lower() == wanted:
                    return eud.uid[len("meshbeacon-") :]
        return None

    def _relay_geochat_reply(self, duck_id: str, message: str) -> None:
        sent = self.send_command(duck_id, message)
        if sent:
            self._logger.info(
                f"MeshBeacon plugin: relayed GeoChat reply to duck_id={duck_id}"
            )
        else:
            self._logger.warning(
                f"MeshBeacon plugin: failed to relay GeoChat reply to duck_id={duck_id} "
                "(bridge not connected/configured)"
            )

    # -- CoT delivery ---------------------------------------------------

    def _get_cot_socket(self) -> socket.socket | None:
        """
        Returns a connected TCP socket to eud_handler's plain-TCP listener,
        (re)connecting lazily if needed. A single long-lived connection is
        reused across events -- eud_handler treats each TCP connection as
        one persistent "EUD", tearing it down and publishing a disconnect
        CoT if we reconnect on every single message.
        """
        with self._lock:
            if self._cot_socket is not None:
                return self._cot_socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect(self._cot_target)
                sock.settimeout(None)
                self._cot_socket = sock
                self._logger.debug(
                    f"MeshBeacon plugin: connected CoT TCP socket to "
                    f"{self._cot_target[0]}:{self._cot_target[1]}"
                )
            except OSError as e:
                self._logger.error(
                    f"MeshBeacon plugin: failed to connect CoT TCP socket to "
                    f"{self._cot_target[0]}:{self._cot_target[1]}: {e}"
                )
                self._cot_socket = None
            return self._cot_socket

    def _send_cot(self, cot_bytes: bytes) -> None:
        sock = self._get_cot_socket()
        if sock is None:
            self._logger.warning("MeshBeacon plugin: no CoT TCP socket available, dropping event")
            return
        try:
            sock.sendall(cot_bytes)
            self._logger.debug(
                f"MeshBeacon plugin: sent {len(cot_bytes)} bytes to "
                f"{self._cot_target[0]}:{self._cot_target[1]}: {cot_bytes.decode('utf-8')}"
            )
        except OSError as e:
            self._logger.warning(f"MeshBeacon plugin: CoT TCP send failed, reconnecting next time: {e}")
            with self._lock:
                try:
                    sock.close()
                except OSError:
                    pass
                if self._cot_socket is sock:
                    self._cot_socket = None

    def _on_message(self, client, userdata, msg) -> None:
        self._logger.debug(
            f"MeshBeacon plugin: MQTT message on {msg.topic!r}, {len(msg.payload)} bytes"
        )
        try:
            envelope = json.loads(msg.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._logger.warning("MeshBeacon plugin: malformed envelope, dropping")
            return

        ciphertext = envelope.get("data")
        if not isinstance(ciphertext, str):
            self._logger.warning("MeshBeacon plugin: envelope missing 'data', dropping")
            return

        plaintext = self._crypto.decrypt_event(ciphertext)
        if plaintext is None:
            self._logger.warning(
                "MeshBeacon plugin: decryption failed (bad auth, malformed payload, or "
                "misconfigured keys), dropping event"
            )
            return

        try:
            data = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._logger.warning("MeshBeacon plugin: decrypted payload was not valid JSON, dropping")
            return

        self._logger.debug(f"MeshBeacon plugin: decrypted event: {data}")

        try:
            self._forward_to_ots(data)
        except BaseException as e:
            self._logger.error(f"MeshBeacon plugin: failed to forward event to OTS: {e}")
            self._logger.debug(traceback.format_exc())

    # -- MeshBeacon event -> CoT --------------------------------------------

    def _ensure_eud(self, uid: str, duck_id: str) -> None:
        """
        Registers a minimal EUD row for this Duck if one doesn't already
        exist. Real ATAK/WinTAK/iTAK clients get an EUD row created by
        eud_handler's TCP/SSL connection handshake, but Ducks are bridged
        in over a raw UDP CoT packet with no equivalent connection step.
        Alert.sender_uid is a NOT NULL foreign key into euds.uid, so
        without this, cot_parser's parse_alert() raises an uncaught
        IntegrityError and every MeshBeacon SOS alert silently fails to
        save -- never appearing in OTS's Alerts UI (CoT/Point rows for the
        same uid also silently fail to insert, per cot_parser.insert_cot's
        own IntegrityError handling).

        `callsign` is set to the duck_id here: unlike the marker/CoT path
        (where the live <contact callsign="duck_id"> is enough for ATAK to
        label the marker), ATAK/WinTAK/iTAK's *Contacts* list -- the thing
        an operator browses to start a private DM -- comes from OTS's
        `/Marti/api/contacts/all`, which serves `EUD.callsign` straight out
        of this table, not anything derived from CoT. Leaving it null (as
        this used to) means every Duck shows up with a blank callsign in
        the Contacts list, making it effectively impossible for an operator
        to find and privately DM it -- GeoChat replies addressed to "" are
        never seen by `_on_geochat_message` either way.
        """
        from opentakserver.extensions import db
        from opentakserver.models.EUD import EUD

        with self._app.app_context():
            existing = db.session.execute(db.session.query(EUD).filter_by(uid=uid)).first()
            if existing:
                eud = existing[0]
                if not eud.callsign:
                    # Upgrade a row created before this fix, so Ducks
                    # registered under the old code eventually become
                    # DM-able too, without needing a manual DB fix.
                    self._set_callsign(db, eud, duck_id)
                else:
                    self._logger.debug(f"MeshBeacon plugin: EUD {uid} already registered")
                return

            eud = EUD()
            eud.uid = uid
            eud.device = "MeshBeacon Duck"
            eud.os = "MeshBeacon"
            eud.platform = "MeshBeacon"

            try:
                db.session.add(eud)
                db.session.flush()
                self._set_callsign(db, eud, duck_id, commit=False)
                db.session.commit()
                self._logger.info(f"MeshBeacon plugin: registered new EUD {uid}")
            except sqlalchemy.exc.IntegrityError as e:
                # Lost a race with another thread inserting the same uid
                self._logger.debug(f"MeshBeacon plugin: EUD {uid} insert raced, rolling back: {e}")
                db.session.rollback()

    def _set_callsign(self, db, eud, duck_id: str, commit: bool = True) -> None:
        """
        EUD.callsign is unique, so a human operator's device (or another
        Duck re-using a callsign some other EUD already took) could
        collide with the bare duck_id -- fall back to a disambiguated
        callsign rather than letting the whole EUD registration fail and
        leaving the Duck permanently un-DM-able.
        """
        candidate = duck_id
        suffix = 2
        while True:
            conflict = db.session.execute(
                db.session.query(eud.__class__)
                .filter_by(callsign=candidate)
                .filter(eud.__class__.uid != eud.uid)
            ).first()
            if not conflict:
                break
            candidate = f"{duck_id}-{suffix}"
            suffix += 1

        eud.callsign = candidate
        if commit:
            try:
                db.session.commit()
                self._logger.info(
                    f"MeshBeacon plugin: set callsign={candidate!r} for EUD {eud.uid}"
                )
            except sqlalchemy.exc.IntegrityError as e:
                self._logger.debug(f"MeshBeacon plugin: callsign update raced, rolling back: {e}")
                db.session.rollback()

    def _forward_to_ots(self, data: dict) -> None:
        lat = data.get("lat")
        lon = data.get("lon")
        if lat is None or lon is None:
            # No coordinates to plot -- nothing useful to send to OTS as a CoT point.
            self._logger.debug(
                f"MeshBeacon plugin: event missing lat/lon, not forwarding: {data}"
            )
            return

        # sos_cancel is a minimal envelope (duck_id/lat/lon/timestamp only,
        # see MeshBeacon's PublishOpenTakSosCancel) telling OTS the incident
        # was resolved -- mirrors ATAK's own <emergency cancel="true"/>
        # convention so the matching Alert's cancel_time gets set instead of
        # it staying active forever.
        is_sos_cancel = bool(data.get("sos_cancel"))
        is_sos = bool(data.get("sos"))

        duck_id = str(data.get("duck_id") or "unknown")
        message = data.get("message") or ""

        self._logger.debug(
            f"MeshBeacon plugin: forwarding duck_id={duck_id} lat={lat} lon={lon} "
            f"sos={is_sos} sos_cancel={is_sos_cancel}"
        )

        try:
            self._ensure_eud(f"meshbeacon-{duck_id}", duck_id)
        except BaseException as e:
            self._logger.error(f"MeshBeacon plugin: failed to register EUD for {duck_id}: {e}")
            self._logger.debug(traceback.format_exc())

        event = self._build_cot(
            duck_id=duck_id,
            lat=float(lat),
            lon=float(lon),
            altitude=data.get("altitude"),
            speed=data.get("speed"),
            heading=data.get("heading"),
            battery=data.get("battery"),
            rssi=data.get("rssi"),
            snr=data.get("snr"),
            message=message,
            is_sos=is_sos,
            is_sos_cancel=is_sos_cancel,
        )

        self._send_cot(tostring(event))

        # A genuine field-device message (free text from the companion
        # phone app, or a canned "Roger" button press -- see MeshBeacon's
        # PublishOpenTakEvent 'chat' flag) additionally becomes a real
        # ATAK GeoChat entry, not just marker remarks. Routine telemetry
        # (gps/sensor pings, SOS) never sets 'chat', so this doesn't spam
        # the chat log.
        if data.get("chat") and message:
            chat_event = self._build_geochat_cot(duck_id, float(lat), float(lon), message)
            self._send_cot(tostring(chat_event))

    def _build_cot(
        self,
        duck_id: str,
        lat: float,
        lon: float,
        altitude: float | None,
        speed: float | None,
        heading: float | None,
        battery: int | None,
        rssi: int | None,
        snr: float | None,
        message: str,
        is_sos: bool,
        is_sos_cancel: bool = False,
    ) -> Element:
        now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        stale = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        event = Element(
            "event",
            {
                "how": "m-g",
                "type": "a-f-G-U-C",
                "version": "2.0",
                "uid": f"meshbeacon-{duck_id}",
                "start": now,
                "time": now,
                "stale": stale,
            },
        )

        # MeshBeacon reports altitude in metres and speed in km/h; CoT's
        # <point hae> is metres and <track speed> is m/s, hence the /3.6.
        SubElement(
            event,
            "point",
            {
                "ce": "9999999.0",
                "le": "9999999.0",
                "hae": str(altitude) if altitude is not None else UNKNOWN,
                "lat": str(lat),
                "lon": str(lon),
            },
        )

        detail = SubElement(event, "detail")
        SubElement(detail, "contact", {"callsign": duck_id, "endpoint": "MeshBeacon"})
        SubElement(detail, "uid", {"Droid": duck_id})
        SubElement(detail, "precisionlocation", {"altsrc": "GPS", "geopointsrc": "GPS"})
        SubElement(
            detail,
            "track",
            {
                "course": str(heading) if heading is not None else UNKNOWN,
                "speed": str(speed / 3.6) if speed is not None else UNKNOWN,
            },
        )

        if battery is not None:
            SubElement(detail, "status", {"battery": str(battery)})

        # Vendor extension (harmless to standard TAK clients, same idiom as
        # OTS's own Meshtastic controller's <__group>/<takv> elements) --
        # RSSI/SNR have no standard CoT element, so they're carried here
        # rather than silently dropped.
        if rssi is not None or snr is not None:
            attrs = {}
            if rssi is not None:
                attrs["rssi"] = str(rssi)
            if snr is not None:
                attrs["snr"] = str(snr)
            SubElement(detail, "meshbeacon", attrs)

        if message:
            remarks = SubElement(detail, "remarks")
            remarks.text = message

        # Mutually exclusive: a cancel tells OTS's cot_parser to close out
        # the most recent open Alert for this uid (see parse_alert's
        # "cancel" branch); an alert opens a new one. Never both on the
        # same event.
        if is_sos_cancel:
            SubElement(detail, "emergency", {"cancel": "true"})
        elif is_sos:
            SubElement(detail, "emergency", {"alert": "true", "type": "MeshBeacon SOS"})

        return event

    def _build_geochat_cot(self, duck_id: str, lat: float, lon: float, message: str) -> Element:
        """
        Builds a real ATAK GeoChat entry (posted to "All Chat Rooms"), the
        same CoT shape OTS's own Meshtastic bridge uses for text messages
        (see controllers/meshtastic_controller.py's text_message()/
        atak_plugin() chat handling) -- type "b-t-f" with a <__chat>/
        <chatgrp> detail, rather than a friendly-unit position report.

        A real (non-zero) <point> is required even though this is a chat
        message, not a location report: cot_parser's parse_point() returns
        None for events with no <point> (or one at exactly 0,0), and
        parse_geochat() then tries to insert a GeoChat row with a NULL
        point_id, which silently fails a NOT NULL/IntegrityError that's
        swallowed with no logging -- the message would be decrypted and
        sent, but never show up anywhere in OTS.
        """
        from_uid = f"meshbeacon-{duck_id}"
        chatroom = "All Chat Rooms"
        message_uid = str(uuid.uuid4())

        now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        stale = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        event = Element(
            "event",
            {
                "how": "h-g-i-g-o",
                "type": "b-t-f",
                "version": "2.0",
                "uid": f"GeoChat.{from_uid}.{chatroom}.{message_uid}",
                "start": now,
                "time": now,
                "stale": stale,
            },
        )

        SubElement(
            event,
            "point",
            {
                "ce": "9999999.0",
                "le": "9999999.0",
                "hae": UNKNOWN,
                "lat": str(lat),
                "lon": str(lon),
            },
        )

        detail = SubElement(event, "detail")
        chat = SubElement(
            detail,
            "__chat",
            {
                "chatroom": chatroom,
                "groupOwner": "false",
                "id": chatroom,
                "messageId": message_uid,
                "parent": "RootContactGroup",
                "senderCallsign": duck_id,
            },
        )
        SubElement(chat, "chatgrp", {"id": chatroom, "uid0": from_uid, "uid1": chatroom})
        SubElement(detail, "link", {"relation": "p-p", "type": "a-f-G-U-C", "uid": from_uid})
        remarks = SubElement(
            detail,
            "remarks",
            {
                "source": f"BAO.F.ATAK.{from_uid}",
                "time": now,
                "to": chatroom,
            },
        )
        remarks.text = message

        return event

    # -- OTS -> MeshBeacon command -------------------------------------------

    def send_command(self, duck_id: str, message: str) -> bool:
        """Encrypt and publish a mesh command to MeshBeacon over the command topic."""
        with self._lock:
            if self._crypto is None or not self._crypto.is_configured() or self._mqtt_client is None:
                return False

            plaintext = json.dumps({"duck_id": duck_id, "message": message}).encode("utf-8")
            encrypted = self._crypto.encrypt_command(plaintext)
            if encrypted is None:
                return False

            envelope = json.dumps({"v": 1, "data": encrypted})
            self._mqtt_client.publish(self._command_topic, envelope, qos=0)

            return True
