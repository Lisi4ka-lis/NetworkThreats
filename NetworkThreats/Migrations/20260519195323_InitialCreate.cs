using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace NetworkThreats.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "mitigation_methods",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    type = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false, defaultValue: "preventive"),
                    short_description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_mitigation_methods", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "threat_categories",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_threat_categories", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "mitigation_steps",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    mitigation_id = table.Column<int>(type: "INTEGER", nullable: false),
                    step_order = table.Column<int>(type: "INTEGER", nullable: false),
                    action = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    applicable_os = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    command_example = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_mitigation_steps", x => x.id);
                    table.ForeignKey(
                        name: "FK_mitigation_steps_mitigation_methods_mitigation_id",
                        column: x => x.mitigation_id,
                        principalTable: "mitigation_methods",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "threats",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    name = table.Column<string>(type: "TEXT", maxLength: 150, nullable: false),
                    category_id = table.Column<int>(type: "INTEGER", nullable: false),
                    short_description = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    severity = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false, defaultValue: "medium"),
                    attack_vector = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    first_detected_year = table.Column<int>(type: "INTEGER", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_threats", x => x.id);
                    table.ForeignKey(
                        name: "FK_threats_threat_categories_category_id",
                        column: x => x.category_id,
                        principalTable: "threat_categories",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "attack_examples",
                columns: table => new
                {
                    id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    name = table.Column<string>(type: "TEXT", maxLength: 150, nullable: false),
                    threat_id = table.Column<int>(type: "INTEGER", nullable: false),
                    year = table.Column<int>(type: "INTEGER", nullable: true),
                    impact_estimate = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    url_reference = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_attack_examples", x => x.id);
                    table.ForeignKey(
                        name: "FK_attack_examples_threats_threat_id",
                        column: x => x.threat_id,
                        principalTable: "threats",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "threat_mitigation",
                columns: table => new
                {
                    threat_id = table.Column<int>(type: "INTEGER", nullable: false),
                    mitigation_id = table.Column<int>(type: "INTEGER", nullable: false),
                    effectiveness = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    notes = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_threat_mitigation", x => new { x.threat_id, x.mitigation_id });
                    table.ForeignKey(
                        name: "FK_threat_mitigation_mitigation_methods_mitigation_id",
                        column: x => x.mitigation_id,
                        principalTable: "mitigation_methods",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_threat_mitigation_threats_threat_id",
                        column: x => x.threat_id,
                        principalTable: "threats",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "mitigation_methods",
                columns: new[] { "id", "name", "short_description", "type" },
                values: new object[,]
                {
                    { 1, "Параметризованные запросы", "Использование подготовленных выражений исключает возможность SQL инъекции.", "preventive" },
                    { 2, "Контентная политика CSP", "HTTP-заголовок Content-Security-Policy ограничивает источники выполняемых скриптов.", "preventive" },
                    { 3, "Анти-DDoS фильтрация", "Специализированные сервисы и оборудование фильтруют аномальный трафик до достижения сервера.", "detective" },
                    { 4, "TLS/HTTPS шифрование", "Шифрование трафика исключает перехват и подмену данных при MitM.", "preventive" },
                    { 5, "Резервное копирование", "Регулярные изолированные резервные копии позволяют восстановить данные после атаки ransomware.", "corrective" },
                    { 6, "Обучение сотрудников", "Информирование пользователей о признаках фишинга снижает вероятность успешной атаки.", "preventive" },
                    { 7, "CSRF-токены", "Уникальные токены в формах подтверждают легитимность запроса и блокируют CSRF.", "preventive" },
                    { 8, "Многофакторная аутентификация", "MFA делает brute force атаки практически бесполезными даже при компрометации пароля.", "preventive" }
                });

            migrationBuilder.InsertData(
                table: "threat_categories",
                columns: new[] { "id", "description", "name" },
                values: new object[,]
                {
                    { 1, "Вирусы, черви, трояны, ransomware", "Вредоносное ПО" },
                    { 2, "DDoS, MitM, сниффинг, спуфинг", "Сетевые атаки" },
                    { 3, "SQL injection, XSS, CSRF", "Web-атаки" },
                    { 4, "Фишинг, претекстинг, вишинг", "Социальная инженерия" }
                });

            migrationBuilder.InsertData(
                table: "mitigation_steps",
                columns: new[] { "id", "action", "applicable_os", "command_example", "mitigation_id", "step_order" },
                values: new object[,]
                {
                    { 1, "Заменить конкатенацию строк в SQL-запросах на параметры (@param)", "Все", null, 1, 1 },
                    { 2, "Применить ORM (Entity Framework) для исключения ручного SQL", "Все", null, 1, 2 },
                    { 3, "Настроить минимальные права учётной записи БД", "Все", null, 1, 3 },
                    { 4, "Получить SSL/TLS сертификат (Let's Encrypt или коммерческий)", "Все", null, 4, 1 },
                    { 5, "Настроить редирект HTTP → HTTPS на веб-сервере", "Linux/Windows", "app.UseHttpsRedirection();", 4, 2 },
                    { 6, "Включить HSTS заголовок для принудительного HTTPS", "Все", "app.UseHsts();", 4, 3 },
                    { 7, "Установить и настроить TOTP-приложение (Google Authenticator)", "Все", null, 8, 1 },
                    { 8, "Включить MFA в настройках ASP.NET Core Identity", "Все", null, 8, 2 }
                });

            migrationBuilder.InsertData(
                table: "threats",
                columns: new[] { "id", "attack_vector", "category_id", "first_detected_year", "name", "severity", "short_description" },
                values: new object[,]
                {
                    { 1, "Веб-формы, параметры URL", 3, 1998, "SQL Injection", "high", "Внедрение вредоносного SQL-кода в запрос к базе данных через пользовательский ввод." },
                    { 2, "Поля ввода, URL-параметры", 3, 2005, "Cross-Site Scripting (XSS)", "medium", "Внедрение вредоносных скриптов в веб-страницу, выполняемых в браузере жертвы." },
                    { 3, "Ботнет, UDP/TCP флуд", 2, 2000, "DDoS-атака", "high", "Перегрузка сервера огромным числом ложных запросов с целью отказа в обслуживании." },
                    { 4, "ARP-спуфинг, подделка DNS", 2, 1995, "Man-in-the-Middle (MitM)", "high", "Перехват и подмена трафика между двумя узлами без их ведома." },
                    { 5, "Электронная почта, уязвимости SMB", 1, 2013, "Ransomware", "critical", "Вредоносное ПО, шифрующее файлы жертвы с требованием выкупа за ключ расшифровки." },
                    { 6, "Email, поддельные веб-сайты", 4, 1996, "Фишинг", "medium", "Мошеннические письма и сайты для кражи учётных данных и персональных сведений." },
                    { 7, "Вредоносная ссылка или страница", 3, 2001, "CSRF", "medium", "Межсайтовая подделка запроса: выполнение нежелательных действий от имени аутентифицированного пользователя." },
                    { 8, "Общая сеть, Wi-Fi без шифрования", 2, 1994, "Сниффинг трафика", "medium", "Перехват сетевых пакетов для извлечения паролей и конфиденциальных данных." },
                    { 9, "SSH, RDP, веб-формы авторизации", 2, 1990, "Brute Force", "medium", "Перебор паролей или ключей шифрования методом полного перебора всех возможных значений." },
                    { 10, "Вложения email, пиратское ПО", 1, 1998, "Троян удалённого доступа", "critical", "Вредоносная программа, предоставляющая злоумышленнику скрытый удалённый доступ к системе жертвы." }
                });

            migrationBuilder.InsertData(
                table: "attack_examples",
                columns: new[] { "id", "impact_estimate", "name", "threat_id", "url_reference", "year" },
                values: new object[,]
                {
                    { 1, "130 млн скомпрометированных карт", "Взлом Heartland Payment Systems", 1, "https://en.wikipedia.org/wiki/Heartland_Payment_Systems", 2008 },
                    { 2, "Крупнейшая на тот момент DDoS-атака", "DDoS на GitHub (1.35 Тбит/с)", 3, "https://github.blog/2018-03-01-ddos-incident-report/", 2018 },
                    { 3, "Ущерб >4 млрд долларов, 200 000 жертв", "WannaCry ransomware", 5, "https://en.wikipedia.org/wiki/WannaCry_ransomware_attack", 2017 },
                    { 4, "Ущерб >10 млрд долларов", "NotPetya", 5, "https://en.wikipedia.org/wiki/2017_cyberattacks_on_Ukraine", 2017 },
                    { 5, "Компрометация сотен TLS-сертификатов", "Атака на DigiNotar", 4, "https://en.wikipedia.org/wiki/DigiNotar", 2011 },
                    { 6, "32 млн паролей в открытом виде", "Взлом RockYou (brute force словарь)", 9, "https://en.wikipedia.org/wiki/RockYou", 2009 }
                });

            migrationBuilder.InsertData(
                table: "threat_mitigation",
                columns: new[] { "mitigation_id", "threat_id", "effectiveness", "notes" },
                values: new object[,]
                {
                    { 1, 1, "high", "Полностью устраняет вектор атаки" },
                    { 2, 2, "high", "CSP блокирует выполнение внешних скриптов" },
                    { 3, 3, "medium", "Снижает нагрузку, но не устраняет атаку полностью" },
                    { 4, 4, "high", "TLS делает перехват трафика бесполезным" },
                    { 5, 5, "high", "Изолированные копии не затрагиваются шифровальщиком" },
                    { 6, 6, "medium", "Снижает вероятность, но не исключает успешный фишинг" },
                    { 7, 7, "high", "CSRF-токен проверяет источник запроса" },
                    { 4, 8, "high", "Шифрование делает перехваченный трафик нечитаемым" },
                    { 8, 9, "high", "Второй фактор блокирует атаку даже при подобранном пароле" },
                    { 6, 10, "medium", "Обучение снижает риск запуска трояна через социальную инженерию" }
                });

            migrationBuilder.CreateIndex(
                name: "IX_attack_examples_threat_id",
                table: "attack_examples",
                column: "threat_id");

            migrationBuilder.CreateIndex(
                name: "IX_mitigation_steps_mitigation_id",
                table: "mitigation_steps",
                column: "mitigation_id");

            migrationBuilder.CreateIndex(
                name: "IX_threat_mitigation_mitigation_id",
                table: "threat_mitigation",
                column: "mitigation_id");

            migrationBuilder.CreateIndex(
                name: "IX_threats_category_id",
                table: "threats",
                column: "category_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "attack_examples");

            migrationBuilder.DropTable(
                name: "mitigation_steps");

            migrationBuilder.DropTable(
                name: "threat_mitigation");

            migrationBuilder.DropTable(
                name: "mitigation_methods");

            migrationBuilder.DropTable(
                name: "threats");

            migrationBuilder.DropTable(
                name: "threat_categories");
        }
    }
}
