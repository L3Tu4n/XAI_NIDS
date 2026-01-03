#!/bin/bash
# Cài đặt Java Development Kit (JDK)
sudo apt update
sudo apt install -y default-jdk
# Cài đặt Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update
sudo apt install -y elasticsearch
# Cấu hình Elasticsearch
sudo bash -c 'echo "network.host: 192.168.63.134" >> /etc/elasticsearch/elasticsearch.yml'
# Khởi động Elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
# Cài đặt Logstash
sudo apt install -y logstash
# Cài đặt Kibana
sudo apt install -y kibana
# Cấu hình Kibana để cho phép truy cập từ IP cụ thể
sudo bash -c 'echo "server.host: 192.168.63.134" >> /etc/kibana/kibana.yml'
# Khởi động Kibana
sudo systemctl enable kibana
sudo systemctl start kibana
# Reset mật khẩu elastic search và tạo token cho kibana
elastic_password=$(echo "y" | sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic | grep -o "New value: .*" | cut -d ' ' -f 3-)
kibana_token=$(sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)
# Hiển thị thông tin đăng nhập
echo "Thông tin đăng nhập:"
echo "-------------------"
echo "Elasticsearch:"
echo "   Tài khoản: elastic"
echo "   Mật khẩu: $elastic_password"
echo ""
echo "Kibana:"
echo "   Token: $kibana_token"
echo ""
cd /usr/share/kibana && sudo bin/kibana-verification-code
