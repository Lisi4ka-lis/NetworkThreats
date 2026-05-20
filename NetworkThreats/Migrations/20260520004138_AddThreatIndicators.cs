using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace NetworkThreats.Migrations
{
    /// <inheritdoc />
    public partial class AddThreatIndicators : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "threat_indicators",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    threat_id = table.Column<int>(type: "INTEGER", nullable: false),
                    indicator_type = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false, defaultValue: "keyword"),
                    pattern = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    confidence = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "medium")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_threat_indicators", x => x.id);
                    table.ForeignKey(
                        name: "FK_threat_indicators_threats_threat_id",
                        column: x => x.threat_id,
                        principalTable: "threats",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "threat_indicators",
                columns: new[] { "id", "confidence", "description", "indicator_type", "pattern", "threat_id" },
                values: new object[,]
                {
                    { 1, "high", "Классическая SQL-инъекция через OR-условие", "keyword", "' OR '1'='1", 1 },
                    { 2, "high", "UNION-based SQL-инъекция для извлечения данных", "keyword", "UNION SELECT", 1 },
                    { 3, "high", "Деструктивная SQL-команда удаления таблицы", "keyword", "DROP TABLE", 1 },
                    { 4, "high", "Выполнение ОС-команд через SQL Server", "keyword", "xp_cmdshell", 1 },
                    { 5, "high", "Цепочка SQL-команд через точку с запятой", "keyword", "'; exec(", 1 },
                    { 6, "medium", "Обход аутентификации с SQL-комментарием", "keyword", "1=1--", 1 },
                    { 7, "medium", "Hex-кодированная SQL-инъекция", "keyword", "CAST(0x", 1 },
                    { 8, "high", "Внедрение JavaScript через тег <script>", "keyword", "<script>", 2 },
                    { 9, "high", "JavaScript URI-схема для XSS", "keyword", "javascript:", 2 },
                    { 10, "high", "Event-handler для выполнения скрипта", "keyword", "onerror=", 2 },
                    { 11, "high", "Кража cookie-файлов через JavaScript", "keyword", "document.cookie", 2 },
                    { 12, "medium", "Динамическое выполнение произвольного кода", "keyword", "eval(", 2 },
                    { 13, "high", "Атака переполнения SYN-пакетами", "keyword", "SYN flood", 3 },
                    { 14, "medium", "Управление ботнетом для DDoS", "keyword", "botnet", 3 },
                    { 15, "medium", "Превышение лимита запросов к серверу", "log_pattern", "too many requests", 3 },
                    { 16, "low", "Отказ в обслуживании — сервер перегружен", "log_pattern", "connection refused", 3 },
                    { 17, "high", "Подмена ARP-записей для перехвата трафика", "keyword", "ARP spoofing", 4 },
                    { 18, "high", "Несоответствие SSL-сертификата — подмена TLS", "log_pattern", "SSL certificate mismatch", 4 },
                    { 19, "medium", "Ошибка сертификата — возможная MitM-атака", "keyword", "certificate error", 4 },
                    { 20, "high", "Инструмент для MitM-атак Ettercap", "keyword", "ettercap", 4 },
                    { 21, "high", "Утилита ARP-спуфинга", "keyword", "arpspoof", 4 },
                    { 22, "high", "Семейство ransomware CryptoLocker", "keyword", "CryptoLocker", 5 },
                    { 23, "high", "Известный шифровальщик WannaCry", "keyword", "WannaCry", 5 },
                    { 24, "high", "Типичное сообщение ransomware", "keyword", "YOUR_FILES_ARE_ENCRYPTED", 5 },
                    { 25, "medium", "Расширение зашифрованных файлов", "keyword", ".encrypted", 5 },
                    { 26, "medium", "Упоминание выкупа", "keyword", "ransom", 5 },
                    { 27, "medium", "Запуск исполняемых файлов из папки Temp", "filepath", "\\Temp\\", 5 },
                    { 28, "high", "Деструктивный шифровальщик NotPetya", "keyword", "NotPetya", 5 },
                    { 29, "high", "Типичная фраза фишинговых писем", "keyword", "verify your account", 6 },
                    { 30, "high", "Психологическое давление в фишинге", "keyword", "your account has been suspended", 6 },
                    { 31, "medium", "Создание срочности в фишинговых атаках", "keyword", "urgent action required", 6 },
                    { 32, "high", "Тайпсквоттинг домена PayPal", "domain", "paypa1.com", 6 },
                    { 33, "medium", "Призыв к действию в фишинговом письме", "keyword", "click here to confirm", 6 },
                    { 34, "high", "Отсутствующий CSRF-токен в запросе", "log_pattern", "missing CSRF token", 7 },
                    { 35, "high", "Недействительный CSRF-токен", "log_pattern", "invalid csrf", 7 },
                    { 36, "low", "Упоминание CSRF в запросе", "keyword", "csrf", 7 },
                    { 37, "high", "Сетевой интерфейс в режиме перехвата пакетов", "keyword", "promiscuous mode", 8 },
                    { 38, "high", "Интерфейс переведён в promiscuous-режим", "log_pattern", "entered promiscuous", 8 },
                    { 39, "medium", "Утилита захвата сетевого трафика", "keyword", "tcpdump", 8 },
                    { 40, "medium", "Анализатор сетевых пакетов", "keyword", "wireshark", 8 },
                    { 41, "high", "Неудачная попытка SSH-аутентификации", "log_pattern", "Failed password for", 9 },
                    { 42, "high", "Попытка входа с несуществующим пользователем", "log_pattern", "Invalid user", 9 },
                    { 43, "medium", "Сбой аутентификации", "log_pattern", "authentication failure", 9 },
                    { 44, "high", "Инструмент брутфорса Hydra", "keyword", "hydra", 9 },
                    { 45, "high", "Инструмент брутфорса Medusa", "keyword", "medusa", 9 },
                    { 46, "high", "Metasploit meterpreter — компонент RAT", "keyword", "meterpreter", 10 },
                    { 47, "high", "Reverse shell через netcat", "keyword", "nc -e", 10 },
                    { 48, "high", "Техника обратного подключения к атакующему", "keyword", "reverse shell", 10 },
                    { 49, "high", "Маскировка RAT под системный процесс svchost", "filepath", "\\Temp\\svchost", 10 },
                    { 50, "high", "Перехватчик нажатий клавиш", "keyword", "keylogger", 10 },
                    { 51, "high", "Обфусцированная команда PowerShell (base64)", "keyword", "powershell -enc", 10 }
                });

            migrationBuilder.CreateIndex(
                name: "IX_threat_indicators_threat_id",
                table: "threat_indicators",
                column: "threat_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "threat_indicators");
        }
    }
}
