import re
import datetime
import re
from collections import defaultdict

class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.attack_ips = set()
        self.attack_logs = []
        self.error_threshold = 5  # макс ошибок 4xx и 5xx в минуту
        self.request_threshold = 20  # макс количества запросов в секунду
        self.request_counts = {}  #  количество запросов за каждую секунду
        self.error_counts = {}  # количество ошибок за каждую минуту

    def analyze(self):
        with open(self.log_file, 'r') as file:
            logs = file.readlines()

        for log in logs:
            self.parse_log(log)

        print("IP-адреса атакующих:", self.attack_ips)
        print("\nПолные логи атаки:")
        for log in self.attack_logs:
            print(log.strip())

    def parse_log(self, log_line):
        match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+) "(.*?)" "(.*?)"', log_line)
        if match:
            ip = match.group(1)
            timestamp = datetime.datetime.strptime(match.group(2), '%d/%b/%Y:%H:%M:%S %z')
            method = match.group(3).split()[0] if match.group(3).split() else ""  # Проверка на пустоту списка
            status_code = int(match.group(4))
            self.check_attack(ip, timestamp, method, status_code)

    def check_attack(self, ip, timestamp, method, status_code):
        # чекаем кол-во запросов
        if self.check_request_rate(ip, timestamp):
            self.attack_ips.add(ip)
            self.attack_logs.append(f"{ip} - - [{timestamp.strftime('%d/%b/%Y:%H:%M:%S %z')}] \"{method} {status_code}\"")

        #Проверка на большое количество ошибок 4xx и 5xx
        if self.check_error_rate(ip, timestamp, status_code):
            self.attack_ips.add(ip)
            self.attack_logs.append(f"{ip} - - [{timestamp.strftime('%d/%b/%Y:%H:%M:%S %z')}] \"{method} {status_code}\"")

        #проверка на отсутствие метода в запросе
        if not method:
            self.attack_ips.add(ip)
            self.attack_logs.append(f"{ip} - - [{timestamp.strftime('%d/%b/%Y:%H:%M:%S %z')}] \"{method} {status_code}\"")

    def check_request_rate(self, ip, timestamp):
            current_second = timestamp.replace(microsecond=0, second=timestamp.second)
            if current_second not in self.request_counts:
                self.request_counts[current_second] = defaultdict(int)
            self.request_counts[current_second][ip] += 1

            # Проверяем количество запросов за последнюю секунду
            if self.request_counts[current_second][ip] > self.request_threshold:
                return True
            return False

    def check_error_rate(self, ip, timestamp, status_code):
            current_minute = timestamp.replace(microsecond=0, second=0, minute=timestamp.minute)
            if current_minute not in self.error_counts:
                self.error_counts[current_minute] = defaultdict(int)

            if 400 <= status_code < 600:
                self.error_counts[current_minute][ip] += 1

            # Проверяем количество ошибок за последнюю минуту
            if self.error_counts[current_minute][ip] > self.error_threshold:
                return True
            return False


analyzer = LogAnalyzer("access.log")  
analyzer.analyze()
