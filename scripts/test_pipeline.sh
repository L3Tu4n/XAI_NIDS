#!/bin/bash
# Test script for ML-NIDS pipeline

echo "========================================"
echo "ML-NIDS Pipeline Test Script"
echo "========================================"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test 1: Kafka Health
echo -e "\n[1/7] Testing Kafka..."
if docker exec kafka /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092 &>/dev/null; then
    echo -e "${GREEN}✓ Kafka is running${NC}"
else
    echo -e "${RED}✗ Kafka is not responding${NC}"
    exit 1
fi

# Test 2: Kafka Topics
echo -e "\n[2/7] Checking Kafka topics..."
TOPICS=$(docker exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list)

if echo "$TOPICS" | grep -q "zeek-logs"; then
    echo -e "${GREEN}✓ Topic 'zeek-logs' exists${NC}"
else
    echo -e "${RED}✗ Topic 'zeek-logs' not found${NC}"
fi

if echo "$TOPICS" | grep -q "ml-predictions"; then
    echo -e "${GREEN}✓ Topic 'ml-predictions' exists${NC}"
else
    echo -e "${RED}✗ Topic 'ml-predictions' not found${NC}"
fi

# Test 3: ML API Health
echo -e "\n[3/7] Testing ML API..."
ML_HEALTH=$(curl -s http://localhost:5000/health)

if echo "$ML_HEALTH" | grep -q "healthy"; then
    echo -e "${GREEN}✓ ML API is healthy${NC}"
    echo "   Response: $ML_HEALTH"
else
    echo -e "${RED}✗ ML API health check failed${NC}"
    exit 1
fi

# Test 4: ML API Model Info
echo -e "\n[4/7] Getting ML API model info..."
MODEL_INFO=$(curl -s http://localhost:5000/model_info)
echo "$MODEL_INFO" | jq '.'

# Test 5: Test Prediction
echo -e "\n[5/7] Testing ML prediction..."
TEST_FEATURES=$(cat <<EOF
{
  "features": {
    "duration": 0.5,
    "total_bytes": 1024,
    "total_pkts": 10,
    "bytes_per_sec": 2048,
    "pkts_per_sec": 20,
    "bytes_per_pkt": 102.4,
    "byte_ratio": 1.0,
    "pkt_ratio": 1.0,
    "proto_numeric": 0,
    "service_encoded": 1,
    "conn_state_encoded": 1,
    "src_conn_count": 5,
    "src_unique_dests": 2,
    "src_unique_ports": 3,
    "dst_conn_count": 1
  }
}
EOF
)

PREDICTION=$(curl -s -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d "$TEST_FEATURES")

if echo "$PREDICTION" | grep -q "attack_type"; then
    echo -e "${GREEN}✓ Prediction successful${NC}"
    echo "$PREDICTION" | jq '.'
else
    echo -e "${RED}✗ Prediction failed${NC}"
    echo "$PREDICTION"
fi

# Test 6: Check Stream Aggregator
echo -e "\n[6/7] Checking Stream Aggregator status..."
if docker compose ps stream-aggregator | grep -q "Up"; then
    echo -e "${GREEN}✓ Stream Aggregator is running${NC}"
    
    # Show recent logs
    echo "Recent logs:"
    docker-compose logs --tail=5 stream-aggregator
else
    echo -e "${RED}✗ Stream Aggregator is not running${NC}"
fi

# Test 7: Check ES Consumer
echo -e "\n[7/7] Checking ES Consumer status..."
if docker compose ps es-consumer | grep -q "Up"; then
    echo -e "${GREEN}✓ ES Consumer is running${NC}"
    
    # Show recent logs
    echo "Recent logs:"
    docker compose logs --tail=5 es-consumer
else
    echo -e "${RED}✗ ES Consumer is not running${NC}"
fi

# Summary
echo -e "\n========================================"
echo "Test Summary"
echo "========================================"

echo -e "\nServices Status:"
docker-compose ps

echo -e "\nKafka Consumer Groups:"
docker exec kafka /opt/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server localhost:9092 --list

echo -e "\n${GREEN}✓ Pipeline test completed!${NC}"
echo "Next steps:"
echo "1. Start Filebeat on Zeek server"
echo "2. Monitor logs: docker-compose logs -f"
echo "3. Check Kafka UI: http://192.168.63.150:8080"
echo "4. Query Elasticsearch for alerts"