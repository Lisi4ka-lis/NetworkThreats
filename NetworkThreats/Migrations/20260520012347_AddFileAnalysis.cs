using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace NetworkThreats.Migrations
{
    /// <inheritdoc />
    public partial class AddFileAnalysis : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "file_heuristics",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    pattern = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    pattern_type = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false, defaultValue: "string"),
                    description = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    category = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false, defaultValue: "general"),
                    risk_level = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "medium")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_file_heuristics", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "known_malicious_hashes",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    sha256 = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    md5 = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    threat_name = table.Column<string>(type: "TEXT", maxLength: 150, nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    severity = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "high"),
                    file_type = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_known_malicious_hashes", x => x.id);
                });

            migrationBuilder.InsertData(
                table: "file_heuristics",
                columns: new[] { "id", "category", "description", "pattern", "pattern_type", "risk_level" },
                values: new object[,]
                {
                    { 1, "Инъекция процесса", "Выделение исполняемой памяти — характерно для шеллкода и инъекций", "VirtualAlloc", "string", "high" },
                    { 2, "Инъекция процесса", "Запись в память стороннего процесса — классическая техника инъекции", "WriteProcessMemory", "string", "high" },
                    { 3, "Инъекция процесса", "Создание потока в удалённом процессе для выполнения произвольного кода", "CreateRemoteThread", "string", "high" },
                    { 4, "Инъекция процесса", "Низкоуровневый Native API для обхода мониторинга безопасности", "NtAllocateVirtualMemory", "string", "high" },
                    { 5, "Выполнение команд", "Запуск командной строки Windows для выполнения команд", "cmd.exe /c", "string", "high" },
                    { 6, "Выполнение команд", "Обфусцированная команда PowerShell (Base64-encoded payload)", "powershell.exe -enc", "string", "high" },
                    { 7, "Выполнение команд", "PowerShell без профилей — обход политик выполнения скриптов", "powershell -nop", "string", "high" },
                    { 8, "Выполнение команд", "Вызов оболочки Bash — типично для Unix reverse shell", "/bin/bash", "string", "medium" },
                    { 9, "Выполнение команд", "Windows API запуска процессов, часто используется вредоносами", "ShellExecute", "string", "medium" },
                    { 10, "Загрузка файлов", "PowerShell-команда загрузки файлов с удалённого сервера", "Invoke-WebRequest", "string", "high" },
                    { 11, "Загрузка файлов", "Злоупотребление certutil для декодирования/загрузки Base64-файлов", "certutil -decode", "string", "high" },
                    { 12, "Загрузка файлов", "Злоупотребление BITS для скрытой загрузки файлов", "bitsadmin /transfer", "string", "high" },
                    { 13, "Загрузка файлов", "Метод WebClient для загрузки файлов в .NET", "DownloadFile(", "string", "medium" },
                    { 14, "Закрепление", "Запись в ключ автозапуска реестра Windows", "CurrentVersion\\Run", "string", "high" },
                    { 15, "Закрепление", "Создание задания планировщика для персистентного запуска", "schtasks /create", "string", "high" },
                    { 16, "Закрепление", "Помещение файла в папку автозапуска Windows", "Startup\\", "string", "medium" },
                    { 17, "Сетевая активность", "Создание сетевого сокета Windows для скрытых коммуникаций", "WSASocket", "string", "medium" },
                    { 18, "Сетевая активность", "WinInet API для скрытых HTTP-запросов", "InternetOpenUrl", "string", "medium" },
                    { 19, "Сетевая активность", "Bash TCP-редирект — техника reverse shell без netcat", "/dev/tcp/", "string", "high" },
                    { 20, "Ransomware", "Windows CryptoAPI шифрование файлов — индикатор шифровальщика", "CryptEncrypt", "string", "high" },
                    { 21, "Ransomware", "Типичное сообщение-вымогатель о шифровании данных", "YOUR FILES ARE ENCRYPTED", "string", "high" },
                    { 22, "Ransomware", "Упоминание криптовалюты — характерно для требований выкупа", "bitcoin", "string", "medium" },
                    { 23, "Анти-анализ", "Проверка наличия отладчика для уклонения от анализа", "IsDebuggerPresent", "string", "medium" },
                    { 24, "Анти-анализ", "Обнаружение VirtualBox — уклонение от виртуальных сред", "VBOX", "string", "medium" },
                    { 25, "Анти-анализ", "Обнаружение VMware — уклонение от виртуальных сред", "VMware", "string", "medium" },
                    { 26, "Макрос Office", "Автозапускаемый VBA-макрос при открытии документа Office", "AutoOpen", "string", "high" },
                    { 27, "Макрос Office", "Выполнение системных команд из VBA-макроса", "Shell(", "string", "high" },
                    { 28, "PDF угрозы", "PDF-действие при открытии — может запускать скрипт или URL", "/OpenAction", "string", "high" },
                    { 29, "PDF угрозы", "JavaScript внутри PDF-файла — типично для эксплойт-документов", "/JavaScript", "string", "high" },
                    { 30, "Упаковщик", "Заголовок UPX-упаковщика — исполняемый файл упакован для обфускации", "UPX0", "string", "medium" }
                });

            migrationBuilder.InsertData(
                table: "known_malicious_hashes",
                columns: new[] { "id", "description", "file_type", "md5", "severity", "sha256", "threat_name" },
                values: new object[,]
                {
                    { 1, "Стандартный тестовый файл EICAR для проверки антивирусного ПО.", "txt", "44d88612fea8a8f36de82e1278abb02f", "medium", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR Test File" },
                    { 2, "Вирус-вымогатель WannaCry 2017 года, использовавший уязвимость EternalBlue (MS17-010).", "exe", "84c82835a5d21bbcf75a61706d8ab549", "critical", "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "WannaCry Ransomware" },
                    { 3, "Деструктивный вирус NotPetya 2017 года, нацеленный на уничтожение MBR и данных.", "exe", "f1394f06cbf1a84d1e14e54b8dd16d5e", "critical", "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745", "NotPetya / Petya" },
                    { 4, "Образец ботнета Mirai, атакующего IoT-устройства через слабые пароли Telnet/SSH.", "exe", "2b28b7f0c7c368b3e82b4f5fa9b51e32", "critical", "8b553571e82e85cf80c7f58acf8fec1e2a1ca0e2cd6c54d5e28c5ec3c04e9e5", "Mirai Botnet Sample" },
                    { 5, "Beacon-агент фреймворка Cobalt Strike, используемый для пентеста и APT-атак.", "dll", "a3b4c5d6e7f8901234567890abcdef12", "high", "4a1f0e6e4e7b1d3f7c2a0b9d5e8f3c1a6b0d2e4f8c7a5b3d9e1f0a2c4b6d8e0", "Cobalt Strike Beacon" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "file_heuristics");

            migrationBuilder.DropTable(
                name: "known_malicious_hashes");
        }
    }
}
