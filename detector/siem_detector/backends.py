"""The two outside systems, behind small interfaces, so that rules and the runner know neither (D7)."""
import base64
import json
import ssl
import time
import urllib.error
import urllib.request


class SearchError(Exception):
    """A query did not give a complete answer. The watermark must not move."""


class OpenSearch:
    def __init__(self, url, ca_file, user, password, timeout=30, retries=3, backoff=2.0, opener=None, sleep=time.sleep):
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.sleep = sleep
        self.auth = 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()
        if opener is None:
            context = ssl.create_default_context(cafile=ca_file)
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context)).open
        self.opener = opener

    def _call(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.url + path, data=data, method=method, headers={'Content-Type': 'application/json', 'Authorization': self.auth})
        return json.load(self.opener(request, timeout=self.timeout))

    def search(self, index, body):
        """Retries transient faults. A partial result is a failure: it would hide events."""
        last = None
        for attempt in range(self.retries):
            if attempt:
                self.sleep(self.backoff * 2 ** (attempt - 1))
            try:
                result = self._call('POST', f'/{index}/_search?allow_partial_search_results=false', body)
            except urllib.error.HTTPError as error:
                last = f'HTTP {error.code}'
                if error.code < 500 and error.code != 429:
                    raise SearchError(last) from error
                continue
            except (OSError, ValueError) as error:
                last = f'{type(error).__name__}: {error}'
                continue
            if result.get('timed_out'):
                last = 'query timed out'
                continue
            if result.get('_shards', {}).get('failed'):
                last = f"{result['_shards']['failed']} shards failed"
                continue
            return result
        raise SearchError(last)

    def index_alert(self, index, alert_id, document):
        """Creates the document once. A second write of the same ID is success, not an error."""
        try:
            self._call('PUT', f'/{index}/_create/{alert_id}', document)
        except urllib.error.HTTPError as error:
            if error.code != 409:
                raise SearchError(f'HTTP {error.code}') from error
        except (OSError, ValueError) as error:
            raise SearchError(f'{type(error).__name__}: {error}') from error


class KafkaPublisher:
    """Idempotent producer. A send is unconfirmed until the broker's delivery report arrives."""

    def __init__(self, bootstrap, topic, delivery_timeout_ms=30000):
        from confluent_kafka import Producer
        self.bootstrap = bootstrap
        self.topic = topic
        self.results = {}
        self.producer = Producer({
            'bootstrap.servers': bootstrap, 'enable.idempotence': True, 'acks': 'all',
            'message.timeout.ms': delivery_timeout_ms, 'linger.ms': 50, 'client.id': 'siem-detector',
            'log_level': 3, 'socket.timeout.ms': 10000,
        })

    def _report(self, error, message):
        self.results[message.key().decode()] = str(error) if error else None

    def send(self, alert_id, payload):
        self.producer.produce(self.topic, key=alert_id.encode(), value=payload.encode(), on_delivery=self._report)

    def poll(self, timeout):
        self.producer.flush(timeout)
        finished, self.results = self.results, {}
        return finished

    def recent_keys(self, tail=5000, timeout=8.0):
        """Keys at the end of the topic. Decides whether an unconfirmed send really arrived."""
        from confluent_kafka import Consumer, TopicPartition
        consumer = Consumer({'bootstrap.servers': self.bootstrap, 'group.id': 'siem-detector-audit', 'enable.auto.commit': False, 'log_level': 3})
        keys = set()
        try:
            names = consumer.list_topics(self.topic, timeout=timeout).topics[self.topic].partitions
            for partition in names:
                low, high = consumer.get_watermark_offsets(TopicPartition(self.topic, partition), timeout=timeout)
                if high <= low:
                    continue
                consumer.assign([TopicPartition(self.topic, partition, max(low, high - tail))])
                position = max(low, high - tail)
                deadline = time.time() + timeout
                while position < high and time.time() < deadline:
                    message = consumer.poll(1.0)
                    if message is None:
                        continue
                    if message.error():
                        raise RuntimeError(str(message.error()))
                    if message.key():
                        keys.add(message.key().decode())
                    position = message.offset() + 1
                if position < high:
                    raise RuntimeError('could not read the end of the alert topic')
        finally:
            consumer.close()
        return keys


class Outbox:
    """Delivers stored alerts: evidence to OpenSearch, then the safe form to Kafka. Retries for ever."""

    def __init__(self, state, store, kafka, log=print):
        self.state = state
        self.store = store
        self.kafka = kafka
        self.log = log
        self.in_flight = set()

    def cycle(self, poll_seconds=5.0):
        rows = self.state.pending()
        if not rows:
            return {'sent': 0, 'failed': 0}
        for alert_id, full, safe, index_done, kafka_done, attempts in rows:
            if index_done:
                continue
            document = json.loads(full)
            try:
                self.store.index_alert(document['evidence_ref'].split('/')[0], alert_id, document)
                self.state.mark_index(alert_id)
            except SearchError as error:
                self.state.mark_attempt(alert_id, error)
        unsent = [r for r in rows if not r[4] and r[0] not in self.in_flight]
        # An earlier send may have reached the broker with its report lost, so look before resending.
        if any(r[5] for r in unsent):
            try:
                present = self.kafka.recent_keys()
            except Exception as error:
                self.log(f'kafka audit failed: {error}')
                return {'sent': 0, 'failed': len(unsent)}
            for row in unsent:
                if row[0] in present:
                    self.state.mark_kafka(row[0])
            unsent = [r for r in unsent if r[0] not in present]
        for alert_id, _, safe, _, _, _ in unsent:
            try:
                self.kafka.send(alert_id, safe)
                self.in_flight.add(alert_id)
                self.state.mark_attempt(alert_id)
            except Exception as error:
                self.state.mark_attempt(alert_id, error)
        sent = failed = 0
        for alert_id, error in self.kafka.poll(poll_seconds).items():
            self.in_flight.discard(alert_id)
            if error:
                failed += 1
                self.state.mark_attempt(alert_id, error)
            else:
                sent += 1
                self.state.mark_kafka(alert_id)
        return {'sent': sent, 'failed': failed}
