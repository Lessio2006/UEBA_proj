# Этот md описывает колонки нашего датасета

# Control
timestamp

# Time features
hour_sin
hour_cos
weekday_sin
weekday_cos
# System
cpu_mean - средняя загрузка CPU за 30 секунд
cpu_max	- максимальная загрузка CPU
ram_mean - среднее использование RAM
ram_max	- максимальное использование RAM
swap_mean - использование файла подкачки
process_count_mean - среднее количество процессов
new_process_count - сколько новых PID появилось
disk_read_bytes	- прочитано байтов за окно
disk_write_bytes - записано байтов за окно
disk_read_ops - количество операций чтения
disk_write_ops - количество операций записи
# Net
net_sent_bytes	отправлено байтов за окно
net_recv_bytes	получено байтов
net_sent_packets отправлено пакетов
net_recv_packets получено пакетов
tcp_connection_count_mean среднее количество TCP-соединений
udp_endpoint_count_mean	количество UDP endpoint
established_count_mean	активные TCP-соединения
listening_count_mean прослушиваемые порты
time_wait_count_mean соединения в TIME_WAIT
new_connection_count новые соединения
closed_connection_count закрытые соединения
unique_remote_host_count число уникальных удалённых узлов
new_remote_host_count ранее не встречавшиеся узлы
unique_remote_port_count число уникальных удалённых портов
public_connection_count_mean соединения с публичными адресами
private_connection_count_mean локальные и частные адреса
outbound_inbound_ratio	отношение исходящего трафика к входящему