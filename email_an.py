import re
import email
from email import policy
import os

class EmailHeaderAnalyzer:
    def __init__(self, raw_email_text):
        # Парсинг сырого текста письма с использованием современной политики обработки
        self.msg = email.message_from_string(raw_email_text, policy=policy.default)
        self.report = {
            "basic_info": {},
            "authentication": {"spf": "НЕ НАЙДЕНО", "dkim": "НЕ НАЙДЕНО", "dmarc": "НЕ НАЙДЕНО"},
            "security_alerts": [],
            "hops": []
        }

    def analyze(self):
        self._extract_basic_info()
        self._analyze_auth_results()
        self._analyze_address_mismatches()
        self._parse_received_hops()
        self._generate_verdict()
        return self.report

    def _extract_basic_info(self):
        self.report["basic_info"] = {
            "Subject": str(self.msg.get("Subject", "[Нет темы]")),
            "From": str(self.msg.get("From", "[Не указан]")),
            "To": str(self.msg.get("To", "[Не указан]")),
            "Date": str(self.msg.get("Date", "[Не указана]")),
            "Message-ID": str(self.msg.get("Message-ID", ""))
        }
        if not self.report["basic_info"]["Message-ID"]:
            self.report["security_alerts"].append("Критический маркер: Отсутствует заголовок Message-ID.")

    def _analyze_auth_results(self):
        # Сбор всех заголовков проверки подлинности (включая ARC для пересылаемых писем)
        auth_headers = self.msg.get_all("Authentication-Results", [])
        arc_auth_headers = self.msg.get_all("ARC-Authentication-Results", [])
       
        # Объединяем заголовки в одну строку для поиска регулярными выражениями
        all_auth = " ".join(list(auth_headers) + list(arc_auth_headers)).lower()

        if all_auth:
            spf_match = re.search(r'spf=([a-z]+)', all_auth)
            dkim_match = re.search(r'dkim=([a-z]+)', all_auth)
            dmarc_match = re.search(r'dmarc=([a-z]+)', all_auth)

            if spf_match:
                status = spf_match.group(1)
                self.report["authentication"]["spf"] = status
                if status in ["fail", "softfail"]:
                    self.report["security_alerts"].append(f"Алерт SPF: Проверка IP-адреса отправителя завершилась со статусом {status.upper()}.")
           
            if dkim_match:
                status = dkim_match.group(1)
                self.report["authentication"]["dkim"] = status
                if status in ["fail"]:
                    self.report["security_alerts"].append("Алерт DKIM: Цифровая подпись невалидна (письмо было изменено или подделано).")

            if dmarc_match:
                status = dmarc_match.group(1)
                self.report["authentication"]["dmarc"] = status
                if status in ["fail"]:
                    self.report["security_alerts"].append("Алерт DMARC: Глобальная политика безопасности домена запрещает прием этого письма (FAIL).")
        else:
            self.report["security_alerts"].append("Внимание: Служебные заголовки проверок (Authentication-Results) отсутствуют.")

    def _analyze_address_mismatches(self):
        from_header = str(self.msg.get("From", ""))
        return_path = str(self.msg.get("Return-Path", ""))

        from_domain = re.search(r'@([a-zA-Z0-9.-]+)', from_header)
        reply_domain = re.search(r'@([a-zA-Z0-9.-]+)', return_path)

        if from_domain and reply_domain:
            f_dom = from_domain.group(1).lower().strip("<>")
            r_dom = reply_domain.group(1).lower().strip("<>")
            if f_dom != r_dom:
                self.report["security_alerts"].append(f"Несоответствие адресов: Домен автора ({f_dom}) отличается от технического домена возврата ({r_dom}). Признак спуфинга!")

    def _parse_received_hops(self):
        received_headers = self.msg.get_all("Received", [])
        if received_headers:
            for i, header in enumerate(received_headers):
                ips = re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', header)
                self.report["hops"].append({
                    "hop_index": i,
                    "raw_header": header.strip().replace('\n', ' '),
                    "extracted_ips": list(set(ips))
                })

    def _generate_verdict(self):
        alerts_count = len(self.report["security_alerts"])
        if alerts_count == 0:
            self.report["verdict"] = "БЕЗОПАСНО (Аномалии не обнаружены)"
        elif alerts_count <= 2:
            self.report["verdict"] = "ПОДОЗРИТЕЛЬНО (Присутствуют маркеры риска)"
        else:
            self.report["verdict"] = "ОПАСНО / ФИШИНГ (Обнаружено множество критических несоответствий)"


def auto_create_sample_file(filename):
    """Создает файл с примером фишингового письма, если файла еще нет"""
    if not os.path.exists(filename):
        sample_data = (
            'From: "Sberbank Support" <security@sberbank-verify-secure.ru>\n'
            'Return-Path: <attacker@bad-server.com>\n'
            'To: user@example.com\n'
            'Subject: Срочно подтвердите ваш аккаунт!\n'
            'Date: Mon, 15 Jun 2026 10:00:00 +0300\n'
            'Message-ID: <123456789@bad-server.com>\n'
            'Authentication-Results: mx.google.com; spf=softfail smtp.mailfrom=attacker@bad-server.com; dmarc=fail\n'
            'Received: from mx.google.com (mx.google.com [173.194.222.26]) by user-mail-router; Mon, 15 Jun 2026 10:02:00 +0300\n'
            'Received: from bad-server.com (unknown [198.51.100.42]) by mx.google.com; Mon, 15 Jun 2026 10:01:00 +0300\n\n'
            'Уважаемый клиент, ваш аккаунт заблокирован...'
        )
        with open(filename, "w", encoding="utf-8") as f:
            f.write(sample_data)


if __name__ == "__main__":
    target_file = "test_email.txt"
   
    # Автоматически создаем тестовый файл, чтобы уберечь пользователя от SyntaxError
    auto_create_sample_file(target_file)
   
    print(f" Читаю заголовки из файла: {target_file}...")
    print("-" * 60)
   
    try:
        with open(target_file, "r", encoding="utf-8") as file:
            raw_email = file.read()
           
        analyzer = EmailHeaderAnalyzer(raw_email)
        results = analyzer.analyze()
       
        print(f"=== РЕЗУЛЬТАТЫ АНАЛИЗА ===")
        print(f"Тема: {results['basic_info']['Subject']}")
        print(f"От кого: {results['basic_info']['From']}")
        print(f"ВЕРДИКТ: {results['verdict']}\n")
       
        if results["security_alerts"]:
            print("Обнаруженные угрозы:")
            for alert in results["security_alerts"]:
                print(f"  [!] {alert}")
        else:
            print(" Подозрительных аномалий в заголовках не найдено.")
           
        if results["hops"]:
            print("\nМаршрут следования письма (IP-адреса узлов):")
            for hop in results["hops"]:
                print(f"  Сервер {hop['hop_index']}: IP -> {hop['extracted_ips']}")
               
    except Exception as e:
        print(f"Произошла непредвиденная ошибка: {e}")


