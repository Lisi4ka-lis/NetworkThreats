using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace NetworkThreats.Migrations
{
    /// <inheritdoc />
    public partial class AddThreatDetails : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "threat_details",
                columns: table => new
                {
                    threat_id = table.Column<int>(type: "INTEGER", nullable: false),
                    mitre_technique_id = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    cvss_score = table.Column<double>(type: "REAL", nullable: true),
                    affected_systems = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    recommended_action = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_threat_details", x => x.threat_id);
                    table.ForeignKey(
                        name: "FK_threat_details_threats_threat_id",
                        column: x => x.threat_id,
                        principalTable: "threats",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "threat_details",
                columns: new[] { "threat_id", "affected_systems", "cvss_score", "mitre_technique_id", "recommended_action" },
                values: new object[,]
                {
                    { 1, "Web-приложения (PHP, ASP.NET, Java EE, Node.js)", 9.8000000000000007, "T1190", "Использовать параметризованные запросы и ORM; минимизировать права учётной записи БД" },
                    { 2, "Браузеры, веб-приложения", 6.0999999999999996, "T1059.007", "Настроить CSP-заголовок; экранировать пользовательский ввод при выводе" },
                    { 3, "Веб-серверы, сетевая инфраструктура, CDN", 7.5, "T1498", "Использовать анти-DDoS сервис (Cloudflare, Qrator); настроить rate limiting" },
                    { 4, "Сетевые коммуникации, Wi-Fi, корпоративные сети", 8.0999999999999996, "T1557", "Принудительно использовать TLS 1.2+; включить HSTS; использовать сертификаты с пиннингом" },
                    { 5, "Windows, Linux, NAS-устройства, серверы VMware", 9.0, "T1486", "Изолированные резервные копии по правилу 3-2-1; своевременно устанавливать патчи" },
                    { 6, "Email-клиенты, пользователи организации", 8.8000000000000007, "T1566", "Обучать сотрудников; настроить SPF/DKIM/DMARC; использовать email-фильтрацию" },
                    { 7, "Веб-приложения с сессионной аутентификацией", 8.8000000000000007, "T1185", "Генерировать и проверять CSRF-токены; использовать атрибут SameSite на Cookie" },
                    { 8, "Незашифрованные сети, Wi-Fi без WPA3, Ethernet", 5.9000000000000004, "T1040", "Шифровать весь трафик (TLS/VPN); использовать коммутаторы с защитой от ARP-спуфинга" },
                    { 9, "SSH, RDP, веб-формы входа, почтовые серверы", 7.5, "T1110", "Включить MFA; ограничить число попыток входа; использовать fail2ban" },
                    { 10, "Windows-конечные точки, корпоративные сети", 9.8000000000000007, "T1219", "Использовать EDR; ограничить автозапуск; мониторить исходящие соединения" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "threat_details");
        }
    }
}
