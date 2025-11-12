# dns-guard (mini)

DNS-фильтр через NFQUEUE + Scapy.
Правила читаются из файла (по строке на правило), первое совпадение даёт `accept`/`drop`.

## Запуск
```bash
sudo apt-get install -y libnetfilter-queue-dev
pip install scapy netfilterqueue
sudo iptables -t mangle -A FORWARD -j NFQUEUE --queue-num 5
sudo python3 main.py --queue 5 --rules rules.dns
```

## Пример правил
```
qname ~ \.zip$ ; action=drop
dst_port in {53,5353} ; action=accept
```
