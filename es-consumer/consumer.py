#!/usr/bin/env python3
"""
Elasticsearch Consumer - FIXED FOR ELASTICSEARCH V8
"""
import json
import logging
import os
import signal
import sys
from datetime import datetime

from confluent_kafka import Consumer, KafkaError
# ⭐️ FIX: Thay ElasticsearchException bằng ApiError và TransportError
from elasticsearch import Elasticsearch, helpers, ApiError, TransportError

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ElasticsearchConsumer:
    def __init__(self):
        # Kafka configuration
        self.bootstrap_servers = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')
        self.topic = os.getenv('KAFKA_PREDICTIONS_TOPIC', 'ml-predictions')
        self.group_id = os.getenv('KAFKA_GROUP_ID', 'es-indexer-group')
        
        # Elasticsearch configuration
        es_hosts = os.getenv('ES_HOSTS', 'https://192.168.63.134:9200')
        self.index_prefix = os.getenv('ES_INDEX', 'ml-nids-alerts') 
        es_username = os.getenv('ES_USERNAME', 'elastic')
        es_password = os.getenv('ES_PASSWORD', '')
        self.verify_certs = os.getenv('ES_VERIFY_CERTS', 'false').lower() == 'true'
        
        # Batch configuration
        self.batch_size = int(os.getenv('BATCH_SIZE', 50))
        self.flush_interval = int(os.getenv('FLUSH_INTERVAL', 5))
        
        logger.info("ES Consumer Configuration (Daily Indexing):")
        logger.info(f"  Kafka Topic: {self.topic}")
        logger.info(f"  ES Hosts: {es_hosts}")
        
        # Initialize Elasticsearch client
        self.es = Elasticsearch(
            [es_hosts],
            basic_auth=(es_username, es_password),
            verify_certs=self.verify_certs,
            ssl_show_warn=False
        )
        
        if self.es.ping():
            logger.info("✓ Connected to Elasticsearch")
        else:
            raise ConnectionError("Failed to connect to Elasticsearch")
        
        self.create_index_template()
        self.init_kafka()
        
        self.buffer = []
        self.last_flush = datetime.now()
        self.stats = {'messages_consumed': 0, 'documents_indexed': 0, 'errors': 0}
        self.running = True

    def create_index_template(self):
        """Tạo Index Template"""
        template_name = f"{self.index_prefix}-template"
        index_pattern = f"{self.index_prefix}-*"
        
        mapping = {
            "properties": {
                "timestamp": {"type": "date"},
                "processed_at": {"type": "date"},
                "window_start": {"type": "date"},
                "src_ip": {"type": "ip"},
                "dst_ip": {"type": "ip"},
                "src_port": {"type": "integer"},
                "dst_port": {"type": "integer"},
                "proto": {"type": "keyword"},
                "service": {"type": "keyword"},
                "uid": {"type": "keyword"},
                "duration": {"type": "float"},
                "orig_bytes": {"type": "long"},
                "resp_bytes": {"type": "long"},
                "orig_pkts": {"type": "long"},
                "resp_pkts": {"type": "long"},
                "conn_state": {"type": "keyword"},
                "src_conn_count": {"type": "integer"},
                "dst_conn_count": {"type": "integer"},
                "is_attack": {"type": "boolean"},
                "attack_type": {"type": "keyword"},
                "predicted_class": {"type": "integer"},
                "confidence": {"type": "float"},
                "attack_probability": {"type": "float"}
            }
        }
        
        try:
            self.es.indices.put_index_template(
                name=template_name,
                index_patterns=[index_pattern],
                template={
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                    "mappings": mapping
                }
            )
            logger.info(f"✅ Index template created: {template_name}")
        # ⭐️ FIX: Catch đúng loại lỗi
        except (ApiError, TransportError) as e:
            logger.error(f"Failed to create index template: {e}")

    def init_kafka(self):
        consumer_conf = {
            'bootstrap.servers': self.bootstrap_servers,
            'group.id': self.group_id,
            'auto.offset.reset': 'latest',
            'enable.auto.commit': True,
            'session.timeout.ms': 90000,
            'max.poll.interval.ms': 600000
        }
        self.consumer = Consumer(consumer_conf)
        self.consumer.subscribe([self.topic])
        logger.info(f"✓ Kafka consumer initialized")

    def _flatten_doc(self, doc):
        flat_doc = doc.copy()
        
        if 'ml_prediction' in flat_doc:
            ml_pred = flat_doc.pop('ml_prediction')
            if isinstance(ml_pred, dict):
                for k, v in ml_pred.items():
                    flat_doc[k] = v
        
        for time_field in ['timestamp', 'window_start']:
            if time_field in flat_doc:
                val = flat_doc[time_field]
                if isinstance(val, str) and ' ' in val:
                    try: flat_doc[time_field] = val.replace(' ', 'T')
                    except: pass
        
        if 'timestamp' not in flat_doc:
            flat_doc['timestamp'] = datetime.utcnow().isoformat()
            
        return flat_doc

    def flush_buffer(self):
        if not self.buffer: return
        
        try:
            today_str = datetime.utcnow().strftime('%Y.%m.%d')
            target_index = f"{self.index_prefix}-{today_str}"
            
            actions = []
            for doc in self.buffer:
                flat_doc = self._flatten_doc(doc)
                action = {
                    "_index": target_index,
                    "_source": flat_doc
                }
                actions.append(action)
            
            success, failed = helpers.bulk(
                self.es, actions, 
                raise_on_error=False,
                stats_only=False
            )
            
            self.stats['documents_indexed'] += success
            
            if failed:
                logger.error(f"Failed to index {len(failed)} docs. First error: {failed[0]}")
                self.stats['errors'] += len(failed)
            
            logger.info(f"📥 Indexed {success} documents to {target_index}")
            
            self.buffer = []
            self.last_flush = datetime.now()
            
        # ⭐️ FIX: Catch đúng loại lỗi
        except (ApiError, TransportError) as e:
            logger.error(f"Bulk index error: {e}")
            self.stats['errors'] += 1
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            self.stats['errors'] += 1

    def run(self):
        logger.info("🚀 Starting message processing...")
        while self.running:
            try:
                msg = self.consumer.poll(1.0)
                
                if (datetime.now() - self.last_flush).total_seconds() >= self.flush_interval:
                    self.flush_buffer()

                if msg is None: continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error(f"Kafka error: {msg.error()}")
                    continue

                try:
                    val = json.loads(msg.value().decode('utf-8'))
                    self.buffer.append(val)
                    self.stats['messages_consumed'] += 1
                    
                    if len(self.buffer) >= self.batch_size:
                        self.flush_buffer()
                except json.JSONDecodeError:
                    pass

            except Exception as e:
                logger.error(f"Loop error: {e}")

    def shutdown(self):
        self.running = False
        self.flush_buffer()
        if self.consumer: self.consumer.close()
        if self.es: self.es.close()
        logger.info("Shutdown complete")

if __name__ == '__main__':
    signal.signal(signal.SIGINT, lambda s, f: consumer.shutdown() if consumer else sys.exit(0))
    signal.signal(signal.SIGTERM, lambda s, f: consumer.shutdown() if consumer else sys.exit(0))
    
    consumer = ElasticsearchConsumer()
    try:
        consumer.run()
    except KeyboardInterrupt:
        consumer.shutdown()