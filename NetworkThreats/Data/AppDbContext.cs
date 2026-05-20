using Microsoft.EntityFrameworkCore;
using NetworkThreats.Models;

namespace NetworkThreats.Data;

/// <summary>
/// Контекст базы данных приложения NetworkThreats.
/// Содержит все DbSet-наборы и конфигурацию Fluent API.
/// </summary>
public class AppDbContext : DbContext
{
    /// <summary>Инициализирует контекст с заданными параметрами подключения.</summary>
    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    { }

    /// <summary>Угрозы информационной безопасности.</summary>
    public DbSet<Threat> Threats { get; set; }

    /// <summary>Категории угроз (Вредоносное ПО, Сетевые атаки и др.).</summary>
    public DbSet<ThreatCategory> ThreatCategories { get; set; }

    /// <summary>Реальные примеры атак, связанные с угрозами.</summary>
    public DbSet<AttackExample> AttackExamples { get; set; }

    /// <summary>Методы защиты от угроз.</summary>
    public DbSet<MitigationMethod> MitigationMethods { get; set; }

    /// <summary>Шаги реализации методов защиты.</summary>
    public DbSet<MitigationStep> MitigationSteps { get; set; }

    /// <summary>Таблица связи N:N между угрозами и методами защиты.</summary>
    public DbSet<ThreatMitigation> ThreatMitigations { get; set; }

    /// <summary>Индикаторы угроз для текстового анализатора.</summary>
    public DbSet<ThreatIndicator> ThreatIndicators { get; set; }

    /// <summary>Расширенные сведения об угрозах (MITRE, CVSS) — отношение 1:1.</summary>
    public DbSet<ThreatDetail> ThreatDetails { get; set; }

    /// <summary>База известных вредоносных файловых хэшей.</summary>
    public DbSet<KnownMaliciousHash> KnownMaliciousHashes { get; set; }

    /// <summary>Эвристические правила статического анализа файлов.</summary>
    public DbSet<FileHeuristic> FileHeuristics { get; set; }

    /// <summary>Настраивает схему БД через Fluent API и заполняет начальные данные.</summary>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // ---- Fluent API: ThreatCategory ----
        modelBuilder.Entity<ThreatCategory>(entity =>
        {
            entity.ToTable("threat_categories");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name)
                  .IsRequired()
                  .HasMaxLength(100);
            entity.Property(e => e.Description)
                  .HasMaxLength(500);
        });

        // ---- Fluent API: Threat ----
        modelBuilder.Entity<Threat>(entity =>
        {
            entity.ToTable("threats");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name)
                  .IsRequired()
                  .HasMaxLength(150);
            entity.Property(e => e.ShortDescription)
                  .IsRequired()
                  .HasMaxLength(2000);
            entity.Property(e => e.Severity)
                  .IsRequired()
                  .HasMaxLength(20)
                  .HasDefaultValue("medium");
            entity.Property(e => e.AttackVector)
                  .HasMaxLength(500);

            entity.HasOne(e => e.Category)
                  .WithMany(c => c.Threats)
                  .HasForeignKey(e => e.CategoryId)
                  .OnDelete(DeleteBehavior.Restrict);
        });

        // ---- Fluent API: AttackExample ----
        modelBuilder.Entity<AttackExample>(entity =>
        {
            entity.ToTable("attack_examples");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name)
                  .IsRequired()
                  .HasMaxLength(150);
            entity.Property(e => e.ImpactEstimate)
                  .HasMaxLength(500);
            entity.Property(e => e.UrlReference)
                  .HasMaxLength(500);

            entity.HasOne(e => e.Threat)
                  .WithMany(t => t.AttackExamples)
                  .HasForeignKey(e => e.ThreatId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ---- Fluent API: MitigationMethod ----
        modelBuilder.Entity<MitigationMethod>(entity =>
        {
            entity.ToTable("mitigation_methods");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name)
                  .IsRequired()
                  .HasMaxLength(100);
            entity.Property(e => e.Type)
                  .IsRequired()
                  .HasMaxLength(50)
                  .HasDefaultValue("preventive");
            entity.Property(e => e.ShortDescription)
                  .HasMaxLength(1000);
        });

        // ---- Fluent API: MitigationStep ----
        modelBuilder.Entity<MitigationStep>(entity =>
        {
            entity.ToTable("mitigation_steps");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Action)
                  .IsRequired()
                  .HasMaxLength(500);
            entity.Property(e => e.ApplicableOs)
                  .HasMaxLength(100);
            entity.Property(e => e.CommandExample)
                  .HasMaxLength(1000);

            entity.HasOne(e => e.MitigationMethod)
                  .WithMany(m => m.MitigationSteps)
                  .HasForeignKey(e => e.MitigationId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ---- Fluent API: ThreatMitigation (составной ключ N:N) ----
        modelBuilder.Entity<ThreatMitigation>(entity =>
        {
            entity.ToTable("threat_mitigation");
            entity.HasKey(e => new { e.ThreatId, e.MitigationId });
            entity.Property(e => e.Effectiveness).HasMaxLength(20);
            entity.Property(e => e.Notes).HasMaxLength(500);

            entity.HasOne(e => e.Threat)
                  .WithMany(t => t.ThreatMitigations)
                  .HasForeignKey(e => e.ThreatId)
                  .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(e => e.MitigationMethod)
                  .WithMany(m => m.ThreatMitigations)
                  .HasForeignKey(e => e.MitigationId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ================================================================
        // SEED DATA
        // ================================================================

        // -- Категории --
        modelBuilder.Entity<ThreatCategory>().HasData(
            new ThreatCategory { Id = 1, Name = "Вредоносное ПО",  Description = "Вирусы, черви, трояны, ransomware" },
            new ThreatCategory { Id = 2, Name = "Сетевые атаки",   Description = "DDoS, MitM, сниффинг, спуфинг" },
            new ThreatCategory { Id = 3, Name = "Web-атаки",       Description = "SQL injection, XSS, CSRF" },
            new ThreatCategory { Id = 4, Name = "Социальная инженерия", Description = "Фишинг, претекстинг, вишинг" }
        );

        // -- Угрозы --
        modelBuilder.Entity<Threat>().HasData(
            new Threat { Id = 1,  Name = "SQL Injection",              CategoryId = 3, Severity = "high",     FirstDetectedYear = 1998, ShortDescription = "Внедрение вредоносного SQL-кода в запрос к базе данных через пользовательский ввод.",            AttackVector = "Веб-формы, параметры URL" },
            new Threat { Id = 2,  Name = "Cross-Site Scripting (XSS)", CategoryId = 3, Severity = "medium",   FirstDetectedYear = 2005, ShortDescription = "Внедрение вредоносных скриптов в веб-страницу, выполняемых в браузере жертвы.",                  AttackVector = "Поля ввода, URL-параметры" },
            new Threat { Id = 3,  Name = "DDoS-атака",                 CategoryId = 2, Severity = "high",     FirstDetectedYear = 2000, ShortDescription = "Перегрузка сервера огромным числом ложных запросов с целью отказа в обслуживании.",               AttackVector = "Ботнет, UDP/TCP флуд" },
            new Threat { Id = 4,  Name = "Man-in-the-Middle (MitM)",   CategoryId = 2, Severity = "high",     FirstDetectedYear = 1995, ShortDescription = "Перехват и подмена трафика между двумя узлами без их ведома.",                                     AttackVector = "ARP-спуфинг, подделка DNS" },
            new Threat { Id = 5,  Name = "Ransomware",                 CategoryId = 1, Severity = "critical", FirstDetectedYear = 2013, ShortDescription = "Вредоносное ПО, шифрующее файлы жертвы с требованием выкупа за ключ расшифровки.",                AttackVector = "Электронная почта, уязвимости SMB" },
            new Threat { Id = 6,  Name = "Фишинг",                     CategoryId = 4, Severity = "medium",   FirstDetectedYear = 1996, ShortDescription = "Мошеннические письма и сайты для кражи учётных данных и персональных сведений.",                 AttackVector = "Email, поддельные веб-сайты" },
            new Threat { Id = 7,  Name = "CSRF",                       CategoryId = 3, Severity = "medium",   FirstDetectedYear = 2001, ShortDescription = "Межсайтовая подделка запроса: выполнение нежелательных действий от имени аутентифицированного пользователя.", AttackVector = "Вредоносная ссылка или страница" },
            new Threat { Id = 8,  Name = "Сниффинг трафика",           CategoryId = 2, Severity = "medium",   FirstDetectedYear = 1994, ShortDescription = "Перехват сетевых пакетов для извлечения паролей и конфиденциальных данных.",                     AttackVector = "Общая сеть, Wi-Fi без шифрования" },
            new Threat { Id = 9,  Name = "Brute Force",                CategoryId = 2, Severity = "medium",   FirstDetectedYear = 1990, ShortDescription = "Перебор паролей или ключей шифрования методом полного перебора всех возможных значений.",         AttackVector = "SSH, RDP, веб-формы авторизации" },
            new Threat { Id = 10, Name = "Троян удалённого доступа",   CategoryId = 1, Severity = "critical", FirstDetectedYear = 1998, ShortDescription = "Вредоносная программа, предоставляющая злоумышленнику скрытый удалённый доступ к системе жертвы.", AttackVector = "Вложения email, пиратское ПО" }
        );

        // -- Методы защиты --
        modelBuilder.Entity<MitigationMethod>().HasData(
            new MitigationMethod { Id = 1, Name = "Параметризованные запросы",  Type = "preventive", ShortDescription = "Использование подготовленных выражений исключает возможность SQL инъекции." },
            new MitigationMethod { Id = 2, Name = "Контентная политика CSP",    Type = "preventive", ShortDescription = "HTTP-заголовок Content-Security-Policy ограничивает источники выполняемых скриптов." },
            new MitigationMethod { Id = 3, Name = "Анти-DDoS фильтрация",       Type = "detective",  ShortDescription = "Специализированные сервисы и оборудование фильтруют аномальный трафик до достижения сервера." },
            new MitigationMethod { Id = 4, Name = "TLS/HTTPS шифрование",       Type = "preventive", ShortDescription = "Шифрование трафика исключает перехват и подмену данных при MitM." },
            new MitigationMethod { Id = 5, Name = "Резервное копирование",      Type = "corrective",  ShortDescription = "Регулярные изолированные резервные копии позволяют восстановить данные после атаки ransomware." },
            new MitigationMethod { Id = 6, Name = "Обучение сотрудников",       Type = "preventive", ShortDescription = "Информирование пользователей о признаках фишинга снижает вероятность успешной атаки." },
            new MitigationMethod { Id = 7, Name = "CSRF-токены",                Type = "preventive", ShortDescription = "Уникальные токены в формах подтверждают легитимность запроса и блокируют CSRF." },
            new MitigationMethod { Id = 8, Name = "Многофакторная аутентификация", Type = "preventive", ShortDescription = "MFA делает brute force атаки практически бесполезными даже при компрометации пароля." }
        );

        // -- Шаги методов защиты --
        modelBuilder.Entity<MitigationStep>().HasData(
            // Параметризованные запросы
            new MitigationStep { Id = 1, MitigationId = 1, StepOrder = 1, Action = "Заменить конкатенацию строк в SQL-запросах на параметры (@param)", ApplicableOs = "Все" },
            new MitigationStep { Id = 2, MitigationId = 1, StepOrder = 2, Action = "Применить ORM (Entity Framework) для исключения ручного SQL", ApplicableOs = "Все" },
            new MitigationStep { Id = 3, MitigationId = 1, StepOrder = 3, Action = "Настроить минимальные права учётной записи БД", ApplicableOs = "Все" },
            // TLS шифрование
            new MitigationStep { Id = 4, MitigationId = 4, StepOrder = 1, Action = "Получить SSL/TLS сертификат (Let's Encrypt или коммерческий)", ApplicableOs = "Все" },
            new MitigationStep { Id = 5, MitigationId = 4, StepOrder = 2, Action = "Настроить редирект HTTP → HTTPS на веб-сервере", ApplicableOs = "Linux/Windows", CommandExample = "app.UseHttpsRedirection();" },
            new MitigationStep { Id = 6, MitigationId = 4, StepOrder = 3, Action = "Включить HSTS заголовок для принудительного HTTPS", ApplicableOs = "Все", CommandExample = "app.UseHsts();" },
            // MFA
            new MitigationStep { Id = 7, MitigationId = 8, StepOrder = 1, Action = "Установить и настроить TOTP-приложение (Google Authenticator)", ApplicableOs = "Все" },
            new MitigationStep { Id = 8, MitigationId = 8, StepOrder = 2, Action = "Включить MFA в настройках ASP.NET Core Identity", ApplicableOs = "Все" }
        );

        // -- Примеры реальных атак --
        modelBuilder.Entity<AttackExample>().HasData(
            new AttackExample { Id = 1, ThreatId = 1, Name = "Взлом Heartland Payment Systems",      Year = 2008, ImpactEstimate = "130 млн скомпрометированных карт",   UrlReference = "https://en.wikipedia.org/wiki/Heartland_Payment_Systems" },
            new AttackExample { Id = 2, ThreatId = 3, Name = "DDoS на GitHub (1.35 Тбит/с)",        Year = 2018, ImpactEstimate = "Крупнейшая на тот момент DDoS-атака", UrlReference = "https://github.blog/2018-03-01-ddos-incident-report/" },
            new AttackExample { Id = 3, ThreatId = 5, Name = "WannaCry ransomware",                  Year = 2017, ImpactEstimate = "Ущерб >4 млрд долларов, 200 000 жертв", UrlReference = "https://en.wikipedia.org/wiki/WannaCry_ransomware_attack" },
            new AttackExample { Id = 4, ThreatId = 5, Name = "NotPetya",                             Year = 2017, ImpactEstimate = "Ущерб >10 млрд долларов",            UrlReference = "https://en.wikipedia.org/wiki/2017_cyberattacks_on_Ukraine" },
            new AttackExample { Id = 5, ThreatId = 4, Name = "Атака на DigiNotar",                  Year = 2011, ImpactEstimate = "Компрометация сотен TLS-сертификатов", UrlReference = "https://en.wikipedia.org/wiki/DigiNotar" },
            new AttackExample { Id = 6, ThreatId = 9, Name = "Взлом RockYou (brute force словарь)", Year = 2009, ImpactEstimate = "32 млн паролей в открытом виде",      UrlReference = "https://en.wikipedia.org/wiki/RockYou" }
        );

        // -- Связи угроза ↔ метод защиты --
        modelBuilder.Entity<ThreatMitigation>().HasData(
            new ThreatMitigation { ThreatId = 1, MitigationId = 1, Effectiveness = "high",   Notes = "Полностью устраняет вектор атаки" },
            new ThreatMitigation { ThreatId = 2, MitigationId = 2, Effectiveness = "high",   Notes = "CSP блокирует выполнение внешних скриптов" },
            new ThreatMitigation { ThreatId = 3, MitigationId = 3, Effectiveness = "medium", Notes = "Снижает нагрузку, но не устраняет атаку полностью" },
            new ThreatMitigation { ThreatId = 4, MitigationId = 4, Effectiveness = "high",   Notes = "TLS делает перехват трафика бесполезным" },
            new ThreatMitigation { ThreatId = 5, MitigationId = 5, Effectiveness = "high",   Notes = "Изолированные копии не затрагиваются шифровальщиком" },
            new ThreatMitigation { ThreatId = 6, MitigationId = 6, Effectiveness = "medium", Notes = "Снижает вероятность, но не исключает успешный фишинг" },
            new ThreatMitigation { ThreatId = 7, MitigationId = 7, Effectiveness = "high",   Notes = "CSRF-токен проверяет источник запроса" },
            new ThreatMitigation { ThreatId = 9, MitigationId = 8, Effectiveness = "high",   Notes = "Второй фактор блокирует атаку даже при подобранном пароле" },
            new ThreatMitigation { ThreatId = 8, MitigationId = 4, Effectiveness = "high",   Notes = "Шифрование делает перехваченный трафик нечитаемым" },
            new ThreatMitigation { ThreatId = 10, MitigationId = 6, Effectiveness = "medium", Notes = "Обучение снижает риск запуска трояна через социальную инженерию" }
        );

        // ---- Fluent API: ThreatDetail (1:1 к Threat) ----
        modelBuilder.Entity<ThreatDetail>(entity =>
        {
            entity.ToTable("threat_details");
            entity.HasKey(e => e.ThreatId);
            entity.Property(e => e.MitreTechniqueId).HasMaxLength(20);
            entity.Property(e => e.AffectedSystems).HasMaxLength(300);
            entity.Property(e => e.RecommendedAction).HasMaxLength(500);

            entity.HasOne(d => d.Threat)
                  .WithOne(t => t.ThreatDetail)
                  .HasForeignKey<ThreatDetail>(d => d.ThreatId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ---- Fluent API: KnownMaliciousHash ----
        modelBuilder.Entity<KnownMaliciousHash>(entity =>
        {
            entity.ToTable("known_malicious_hashes");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Sha256).IsRequired().HasMaxLength(64);
            entity.Property(e => e.Md5).HasMaxLength(32);
            entity.Property(e => e.ThreatName).IsRequired().HasMaxLength(150);
            entity.Property(e => e.Description).HasMaxLength(500);
            entity.Property(e => e.Severity).HasMaxLength(20).HasDefaultValue("high");
            entity.Property(e => e.FileType).HasMaxLength(50);
        });

        // ---- Fluent API: FileHeuristic ----
        modelBuilder.Entity<FileHeuristic>(entity =>
        {
            entity.ToTable("file_heuristics");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Pattern).IsRequired().HasMaxLength(200);
            entity.Property(e => e.PatternType).IsRequired().HasMaxLength(50).HasDefaultValue("string");
            entity.Property(e => e.Description).IsRequired().HasMaxLength(300);
            entity.Property(e => e.Category).HasMaxLength(100).HasDefaultValue("general");
            entity.Property(e => e.RiskLevel).HasMaxLength(20).HasDefaultValue("medium");
        });

        // ---- Fluent API: ThreatIndicator ----
        modelBuilder.Entity<ThreatIndicator>(entity =>
        {
            entity.ToTable("threat_indicators");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.IndicatorType).IsRequired().HasMaxLength(50).HasDefaultValue("keyword");
            entity.Property(e => e.Pattern).IsRequired().HasMaxLength(500);
            entity.Property(e => e.Description).HasMaxLength(300);
            entity.Property(e => e.Confidence).HasMaxLength(20).HasDefaultValue("medium");

            entity.HasOne(e => e.Threat)
                  .WithMany()
                  .HasForeignKey(e => e.ThreatId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // ================================================================
        // SEED: Расширенные описания угроз (1:1)
        // ================================================================
        modelBuilder.Entity<ThreatDetail>().HasData(
            new ThreatDetail { ThreatId = 1,  MitreTechniqueId = "T1190", CvssScore = 9.8, AffectedSystems = "Web-приложения (PHP, ASP.NET, Java EE, Node.js)",    RecommendedAction = "Использовать параметризованные запросы и ORM; минимизировать права учётной записи БД" },
            new ThreatDetail { ThreatId = 2,  MitreTechniqueId = "T1059.007", CvssScore = 6.1, AffectedSystems = "Браузеры, веб-приложения",                      RecommendedAction = "Настроить CSP-заголовок; экранировать пользовательский ввод при выводе" },
            new ThreatDetail { ThreatId = 3,  MitreTechniqueId = "T1498", CvssScore = 7.5, AffectedSystems = "Веб-серверы, сетевая инфраструктура, CDN",           RecommendedAction = "Использовать анти-DDoS сервис (Cloudflare, Qrator); настроить rate limiting" },
            new ThreatDetail { ThreatId = 4,  MitreTechniqueId = "T1557", CvssScore = 8.1, AffectedSystems = "Сетевые коммуникации, Wi-Fi, корпоративные сети",    RecommendedAction = "Принудительно использовать TLS 1.2+; включить HSTS; использовать сертификаты с пиннингом" },
            new ThreatDetail { ThreatId = 5,  MitreTechniqueId = "T1486", CvssScore = 9.0, AffectedSystems = "Windows, Linux, NAS-устройства, серверы VMware",     RecommendedAction = "Изолированные резервные копии по правилу 3-2-1; своевременно устанавливать патчи" },
            new ThreatDetail { ThreatId = 6,  MitreTechniqueId = "T1566", CvssScore = 8.8, AffectedSystems = "Email-клиенты, пользователи организации",            RecommendedAction = "Обучать сотрудников; настроить SPF/DKIM/DMARC; использовать email-фильтрацию" },
            new ThreatDetail { ThreatId = 7,  MitreTechniqueId = "T1185", CvssScore = 8.8, AffectedSystems = "Веб-приложения с сессионной аутентификацией",        RecommendedAction = "Генерировать и проверять CSRF-токены; использовать атрибут SameSite на Cookie" },
            new ThreatDetail { ThreatId = 8,  MitreTechniqueId = "T1040", CvssScore = 5.9, AffectedSystems = "Незашифрованные сети, Wi-Fi без WPA3, Ethernet",     RecommendedAction = "Шифровать весь трафик (TLS/VPN); использовать коммутаторы с защитой от ARP-спуфинга" },
            new ThreatDetail { ThreatId = 9,  MitreTechniqueId = "T1110", CvssScore = 7.5, AffectedSystems = "SSH, RDP, веб-формы входа, почтовые серверы",        RecommendedAction = "Включить MFA; ограничить число попыток входа; использовать fail2ban" },
            new ThreatDetail { ThreatId = 10, MitreTechniqueId = "T1219", CvssScore = 9.8, AffectedSystems = "Windows-конечные точки, корпоративные сети",         RecommendedAction = "Использовать EDR; ограничить автозапуск; мониторить исходящие соединения" }
        );

        // ================================================================
        // SEED: Индикаторы угроз (правила анализатора)
        // ================================================================
        modelBuilder.Entity<ThreatIndicator>().HasData(
            // -- SQL Injection (ThreatId=1) --
            new ThreatIndicator { Id = 1,  ThreatId = 1, IndicatorType = "keyword",     Confidence = "high",   Pattern = "' OR '1'='1",          Description = "Классическая SQL-инъекция через OR-условие" },
            new ThreatIndicator { Id = 2,  ThreatId = 1, IndicatorType = "keyword",     Confidence = "high",   Pattern = "UNION SELECT",          Description = "UNION-based SQL-инъекция для извлечения данных" },
            new ThreatIndicator { Id = 3,  ThreatId = 1, IndicatorType = "keyword",     Confidence = "high",   Pattern = "DROP TABLE",            Description = "Деструктивная SQL-команда удаления таблицы" },
            new ThreatIndicator { Id = 4,  ThreatId = 1, IndicatorType = "keyword",     Confidence = "high",   Pattern = "xp_cmdshell",           Description = "Выполнение ОС-команд через SQL Server" },
            new ThreatIndicator { Id = 5,  ThreatId = 1, IndicatorType = "keyword",     Confidence = "high",   Pattern = "'; exec(",              Description = "Цепочка SQL-команд через точку с запятой" },
            new ThreatIndicator { Id = 6,  ThreatId = 1, IndicatorType = "keyword",     Confidence = "medium", Pattern = "1=1--",                 Description = "Обход аутентификации с SQL-комментарием" },
            new ThreatIndicator { Id = 7,  ThreatId = 1, IndicatorType = "keyword",     Confidence = "medium", Pattern = "CAST(0x",               Description = "Hex-кодированная SQL-инъекция" },

            // -- XSS (ThreatId=2) --
            new ThreatIndicator { Id = 8,  ThreatId = 2, IndicatorType = "keyword",     Confidence = "high",   Pattern = "<script>",              Description = "Внедрение JavaScript через тег <script>" },
            new ThreatIndicator { Id = 9,  ThreatId = 2, IndicatorType = "keyword",     Confidence = "high",   Pattern = "javascript:",           Description = "JavaScript URI-схема для XSS" },
            new ThreatIndicator { Id = 10, ThreatId = 2, IndicatorType = "keyword",     Confidence = "high",   Pattern = "onerror=",              Description = "Event-handler для выполнения скрипта" },
            new ThreatIndicator { Id = 11, ThreatId = 2, IndicatorType = "keyword",     Confidence = "high",   Pattern = "document.cookie",       Description = "Кража cookie-файлов через JavaScript" },
            new ThreatIndicator { Id = 12, ThreatId = 2, IndicatorType = "keyword",     Confidence = "medium", Pattern = "eval(",                 Description = "Динамическое выполнение произвольного кода" },

            // -- DDoS (ThreatId=3) --
            new ThreatIndicator { Id = 13, ThreatId = 3, IndicatorType = "keyword",     Confidence = "high",   Pattern = "SYN flood",             Description = "Атака переполнения SYN-пакетами" },
            new ThreatIndicator { Id = 14, ThreatId = 3, IndicatorType = "keyword",     Confidence = "medium", Pattern = "botnet",                Description = "Управление ботнетом для DDoS" },
            new ThreatIndicator { Id = 15, ThreatId = 3, IndicatorType = "log_pattern", Confidence = "medium", Pattern = "too many requests",     Description = "Превышение лимита запросов к серверу" },
            new ThreatIndicator { Id = 16, ThreatId = 3, IndicatorType = "log_pattern", Confidence = "low",    Pattern = "connection refused",    Description = "Отказ в обслуживании — сервер перегружен" },

            // -- MitM (ThreatId=4) --
            new ThreatIndicator { Id = 17, ThreatId = 4, IndicatorType = "keyword",     Confidence = "high",   Pattern = "ARP spoofing",          Description = "Подмена ARP-записей для перехвата трафика" },
            new ThreatIndicator { Id = 18, ThreatId = 4, IndicatorType = "log_pattern", Confidence = "high",   Pattern = "SSL certificate mismatch", Description = "Несоответствие SSL-сертификата — подмена TLS" },
            new ThreatIndicator { Id = 19, ThreatId = 4, IndicatorType = "keyword",     Confidence = "medium", Pattern = "certificate error",     Description = "Ошибка сертификата — возможная MitM-атака" },
            new ThreatIndicator { Id = 20, ThreatId = 4, IndicatorType = "keyword",     Confidence = "high",   Pattern = "ettercap",              Description = "Инструмент для MitM-атак Ettercap" },
            new ThreatIndicator { Id = 21, ThreatId = 4, IndicatorType = "keyword",     Confidence = "high",   Pattern = "arpspoof",              Description = "Утилита ARP-спуфинга" },

            // -- Ransomware (ThreatId=5) --
            new ThreatIndicator { Id = 22, ThreatId = 5, IndicatorType = "keyword",     Confidence = "high",   Pattern = "CryptoLocker",          Description = "Семейство ransomware CryptoLocker" },
            new ThreatIndicator { Id = 23, ThreatId = 5, IndicatorType = "keyword",     Confidence = "high",   Pattern = "WannaCry",              Description = "Известный шифровальщик WannaCry" },
            new ThreatIndicator { Id = 24, ThreatId = 5, IndicatorType = "keyword",     Confidence = "high",   Pattern = "YOUR_FILES_ARE_ENCRYPTED", Description = "Типичное сообщение ransomware" },
            new ThreatIndicator { Id = 25, ThreatId = 5, IndicatorType = "keyword",     Confidence = "medium", Pattern = ".encrypted",            Description = "Расширение зашифрованных файлов" },
            new ThreatIndicator { Id = 26, ThreatId = 5, IndicatorType = "keyword",     Confidence = "medium", Pattern = "ransom",                Description = "Упоминание выкупа" },
            new ThreatIndicator { Id = 27, ThreatId = 5, IndicatorType = "filepath",    Confidence = "medium", Pattern = "\\Temp\\",              Description = "Запуск исполняемых файлов из папки Temp" },
            new ThreatIndicator { Id = 28, ThreatId = 5, IndicatorType = "keyword",     Confidence = "high",   Pattern = "NotPetya",              Description = "Деструктивный шифровальщик NotPetya" },

            // -- Фишинг (ThreatId=6) --
            new ThreatIndicator { Id = 29, ThreatId = 6, IndicatorType = "keyword",     Confidence = "high",   Pattern = "verify your account",   Description = "Типичная фраза фишинговых писем" },
            new ThreatIndicator { Id = 30, ThreatId = 6, IndicatorType = "keyword",     Confidence = "high",   Pattern = "your account has been suspended", Description = "Психологическое давление в фишинге" },
            new ThreatIndicator { Id = 31, ThreatId = 6, IndicatorType = "keyword",     Confidence = "medium", Pattern = "urgent action required", Description = "Создание срочности в фишинговых атаках" },
            new ThreatIndicator { Id = 32, ThreatId = 6, IndicatorType = "domain",      Confidence = "high",   Pattern = "paypa1.com",            Description = "Тайпсквоттинг домена PayPal" },
            new ThreatIndicator { Id = 33, ThreatId = 6, IndicatorType = "keyword",     Confidence = "medium", Pattern = "click here to confirm", Description = "Призыв к действию в фишинговом письме" },

            // -- CSRF (ThreatId=7) --
            new ThreatIndicator { Id = 34, ThreatId = 7, IndicatorType = "log_pattern", Confidence = "high",   Pattern = "missing CSRF token",    Description = "Отсутствующий CSRF-токен в запросе" },
            new ThreatIndicator { Id = 35, ThreatId = 7, IndicatorType = "log_pattern", Confidence = "high",   Pattern = "invalid csrf",          Description = "Недействительный CSRF-токен" },
            new ThreatIndicator { Id = 36, ThreatId = 7, IndicatorType = "keyword",     Confidence = "low",    Pattern = "csrf",                  Description = "Упоминание CSRF в запросе" },

            // -- Сниффинг (ThreatId=8) --
            new ThreatIndicator { Id = 37, ThreatId = 8, IndicatorType = "keyword",     Confidence = "high",   Pattern = "promiscuous mode",      Description = "Сетевой интерфейс в режиме перехвата пакетов" },
            new ThreatIndicator { Id = 38, ThreatId = 8, IndicatorType = "log_pattern", Confidence = "high",   Pattern = "entered promiscuous",   Description = "Интерфейс переведён в promiscuous-режим" },
            new ThreatIndicator { Id = 39, ThreatId = 8, IndicatorType = "keyword",     Confidence = "medium", Pattern = "tcpdump",               Description = "Утилита захвата сетевого трафика" },
            new ThreatIndicator { Id = 40, ThreatId = 8, IndicatorType = "keyword",     Confidence = "medium", Pattern = "wireshark",             Description = "Анализатор сетевых пакетов" },

            // -- Brute Force (ThreatId=9) --
            new ThreatIndicator { Id = 41, ThreatId = 9, IndicatorType = "log_pattern", Confidence = "high",   Pattern = "Failed password for",   Description = "Неудачная попытка SSH-аутентификации" },
            new ThreatIndicator { Id = 42, ThreatId = 9, IndicatorType = "log_pattern", Confidence = "high",   Pattern = "Invalid user",          Description = "Попытка входа с несуществующим пользователем" },
            new ThreatIndicator { Id = 43, ThreatId = 9, IndicatorType = "log_pattern", Confidence = "medium", Pattern = "authentication failure", Description = "Сбой аутентификации" },
            new ThreatIndicator { Id = 44, ThreatId = 9, IndicatorType = "keyword",     Confidence = "high",   Pattern = "hydra",                 Description = "Инструмент брутфорса Hydra" },
            new ThreatIndicator { Id = 45, ThreatId = 9, IndicatorType = "keyword",     Confidence = "high",   Pattern = "medusa",                Description = "Инструмент брутфорса Medusa" },

            // -- RAT (ThreatId=10) --
            new ThreatIndicator { Id = 46, ThreatId = 10, IndicatorType = "keyword",    Confidence = "high",   Pattern = "meterpreter",           Description = "Metasploit meterpreter — компонент RAT" },
            new ThreatIndicator { Id = 47, ThreatId = 10, IndicatorType = "keyword",    Confidence = "high",   Pattern = "nc -e",                 Description = "Reverse shell через netcat" },
            new ThreatIndicator { Id = 48, ThreatId = 10, IndicatorType = "keyword",    Confidence = "high",   Pattern = "reverse shell",         Description = "Техника обратного подключения к атакующему" },
            new ThreatIndicator { Id = 49, ThreatId = 10, IndicatorType = "filepath",   Confidence = "high",   Pattern = "\\Temp\\svchost",       Description = "Маскировка RAT под системный процесс svchost" },
            new ThreatIndicator { Id = 50, ThreatId = 10, IndicatorType = "keyword",    Confidence = "high",   Pattern = "keylogger",             Description = "Перехватчик нажатий клавиш" },
            new ThreatIndicator { Id = 51, ThreatId = 10, IndicatorType = "keyword",    Confidence = "high",   Pattern = "powershell -enc",       Description = "Обфусцированная команда PowerShell (base64)" }
        );

        // ================================================================
        // SEED: Известные вредоносные хэши
        // ================================================================
        modelBuilder.Entity<KnownMaliciousHash>().HasData(
            new KnownMaliciousHash
            {
                Id = 1, Severity = "medium", FileType = "txt",
                ThreatName = "EICAR Test File",
                Sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                Md5    = "44d88612fea8a8f36de82e1278abb02f",
                Description = "Стандартный тестовый файл EICAR для проверки антивирусного ПО."
            },
            new KnownMaliciousHash
            {
                Id = 2, Severity = "critical", FileType = "exe",
                ThreatName = "WannaCry Ransomware",
                Sha256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
                Md5    = "84c82835a5d21bbcf75a61706d8ab549",
                Description = "Вирус-вымогатель WannaCry 2017 года, использовавший уязвимость EternalBlue (MS17-010)."
            },
            new KnownMaliciousHash
            {
                Id = 3, Severity = "critical", FileType = "exe",
                ThreatName = "NotPetya / Petya",
                Sha256 = "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
                Md5    = "f1394f06cbf1a84d1e14e54b8dd16d5e",
                Description = "Деструктивный вирус NotPetya 2017 года, нацеленный на уничтожение MBR и данных."
            },
            new KnownMaliciousHash
            {
                Id = 4, Severity = "critical", FileType = "exe",
                ThreatName = "Mirai Botnet Sample",
                Sha256 = "8b553571e82e85cf80c7f58acf8fec1e2a1ca0e2cd6c54d5e28c5ec3c04e9e5",
                Md5    = "2b28b7f0c7c368b3e82b4f5fa9b51e32",
                Description = "Образец ботнета Mirai, атакующего IoT-устройства через слабые пароли Telnet/SSH."
            },
            new KnownMaliciousHash
            {
                Id = 5, Severity = "high", FileType = "dll",
                ThreatName = "Cobalt Strike Beacon",
                Sha256 = "4a1f0e6e4e7b1d3f7c2a0b9d5e8f3c1a6b0d2e4f8c7a5b3d9e1f0a2c4b6d8e0",
                Md5    = "a3b4c5d6e7f8901234567890abcdef12",
                Description = "Beacon-агент фреймворка Cobalt Strike, используемый для пентеста и APT-атак."
            }
        );

        // ================================================================
        // SEED: Эвристические правила анализа файлов
        // ================================================================
        modelBuilder.Entity<FileHeuristic>().HasData(
            // -- Process injection --
            new FileHeuristic { Id = 1,  PatternType = "string", RiskLevel = "high",   Category = "Инъекция процесса", Pattern = "VirtualAlloc",          Description = "Выделение исполняемой памяти — характерно для шеллкода и инъекций" },
            new FileHeuristic { Id = 2,  PatternType = "string", RiskLevel = "high",   Category = "Инъекция процесса", Pattern = "WriteProcessMemory",    Description = "Запись в память стороннего процесса — классическая техника инъекции" },
            new FileHeuristic { Id = 3,  PatternType = "string", RiskLevel = "high",   Category = "Инъекция процесса", Pattern = "CreateRemoteThread",    Description = "Создание потока в удалённом процессе для выполнения произвольного кода" },
            new FileHeuristic { Id = 4,  PatternType = "string", RiskLevel = "high",   Category = "Инъекция процесса", Pattern = "NtAllocateVirtualMemory", Description = "Низкоуровневый Native API для обхода мониторинга безопасности" },

            // -- Shell execution --
            new FileHeuristic { Id = 5,  PatternType = "string", RiskLevel = "high",   Category = "Выполнение команд", Pattern = "cmd.exe /c",            Description = "Запуск командной строки Windows для выполнения команд" },
            new FileHeuristic { Id = 6,  PatternType = "string", RiskLevel = "high",   Category = "Выполнение команд", Pattern = "powershell.exe -enc",   Description = "Обфусцированная команда PowerShell (Base64-encoded payload)" },
            new FileHeuristic { Id = 7,  PatternType = "string", RiskLevel = "high",   Category = "Выполнение команд", Pattern = "powershell -nop",       Description = "PowerShell без профилей — обход политик выполнения скриптов" },
            new FileHeuristic { Id = 8,  PatternType = "string", RiskLevel = "medium", Category = "Выполнение команд", Pattern = "/bin/bash",             Description = "Вызов оболочки Bash — типично для Unix reverse shell" },
            new FileHeuristic { Id = 9,  PatternType = "string", RiskLevel = "medium", Category = "Выполнение команд", Pattern = "ShellExecute",          Description = "Windows API запуска процессов, часто используется вредоносами" },

            // -- Download cradles --
            new FileHeuristic { Id = 10, PatternType = "string", RiskLevel = "high",   Category = "Загрузка файлов",   Pattern = "Invoke-WebRequest",     Description = "PowerShell-команда загрузки файлов с удалённого сервера" },
            new FileHeuristic { Id = 11, PatternType = "string", RiskLevel = "high",   Category = "Загрузка файлов",   Pattern = "certutil -decode",      Description = "Злоупотребление certutil для декодирования/загрузки Base64-файлов" },
            new FileHeuristic { Id = 12, PatternType = "string", RiskLevel = "high",   Category = "Загрузка файлов",   Pattern = "bitsadmin /transfer",   Description = "Злоупотребление BITS для скрытой загрузки файлов" },
            new FileHeuristic { Id = 13, PatternType = "string", RiskLevel = "medium", Category = "Загрузка файлов",   Pattern = "DownloadFile(",         Description = "Метод WebClient для загрузки файлов в .NET" },

            // -- Persistence --
            new FileHeuristic { Id = 14, PatternType = "string", RiskLevel = "high",   Category = "Закрепление",       Pattern = "CurrentVersion\\Run",   Description = "Запись в ключ автозапуска реестра Windows" },
            new FileHeuristic { Id = 15, PatternType = "string", RiskLevel = "high",   Category = "Закрепление",       Pattern = "schtasks /create",      Description = "Создание задания планировщика для персистентного запуска" },
            new FileHeuristic { Id = 16, PatternType = "string", RiskLevel = "medium", Category = "Закрепление",       Pattern = "Startup\\",             Description = "Помещение файла в папку автозапуска Windows" },

            // -- Network --
            new FileHeuristic { Id = 17, PatternType = "string", RiskLevel = "medium", Category = "Сетевая активность", Pattern = "WSASocket",            Description = "Создание сетевого сокета Windows для скрытых коммуникаций" },
            new FileHeuristic { Id = 18, PatternType = "string", RiskLevel = "medium", Category = "Сетевая активность", Pattern = "InternetOpenUrl",      Description = "WinInet API для скрытых HTTP-запросов" },
            new FileHeuristic { Id = 19, PatternType = "string", RiskLevel = "high",   Category = "Сетевая активность", Pattern = "/dev/tcp/",            Description = "Bash TCP-редирект — техника reverse shell без netcat" },

            // -- Crypto / Ransomware --
            new FileHeuristic { Id = 20, PatternType = "string", RiskLevel = "high",   Category = "Ransomware",        Pattern = "CryptEncrypt",          Description = "Windows CryptoAPI шифрование файлов — индикатор шифровальщика" },
            new FileHeuristic { Id = 21, PatternType = "string", RiskLevel = "high",   Category = "Ransomware",        Pattern = "YOUR FILES ARE ENCRYPTED", Description = "Типичное сообщение-вымогатель о шифровании данных" },
            new FileHeuristic { Id = 22, PatternType = "string", RiskLevel = "medium", Category = "Ransomware",        Pattern = "bitcoin",               Description = "Упоминание криптовалюты — характерно для требований выкупа" },

            // -- Anti-analysis --
            new FileHeuristic { Id = 23, PatternType = "string", RiskLevel = "medium", Category = "Анти-анализ",       Pattern = "IsDebuggerPresent",     Description = "Проверка наличия отладчика для уклонения от анализа" },
            new FileHeuristic { Id = 24, PatternType = "string", RiskLevel = "medium", Category = "Анти-анализ",       Pattern = "VBOX",                  Description = "Обнаружение VirtualBox — уклонение от виртуальных сред" },
            new FileHeuristic { Id = 25, PatternType = "string", RiskLevel = "medium", Category = "Анти-анализ",       Pattern = "VMware",                Description = "Обнаружение VMware — уклонение от виртуальных сред" },

            // -- Office macros / PDF --
            new FileHeuristic { Id = 26, PatternType = "string", RiskLevel = "high",   Category = "Макрос Office",     Pattern = "AutoOpen",              Description = "Автозапускаемый VBA-макрос при открытии документа Office" },
            new FileHeuristic { Id = 27, PatternType = "string", RiskLevel = "high",   Category = "Макрос Office",     Pattern = "Shell(",                Description = "Выполнение системных команд из VBA-макроса" },
            new FileHeuristic { Id = 28, PatternType = "string", RiskLevel = "high",   Category = "PDF угрозы",        Pattern = "/OpenAction",           Description = "PDF-действие при открытии — может запускать скрипт или URL" },
            new FileHeuristic { Id = 29, PatternType = "string", RiskLevel = "high",   Category = "PDF угрозы",        Pattern = "/JavaScript",           Description = "JavaScript внутри PDF-файла — типично для эксплойт-документов" },

            // -- Packed/encoded --
            new FileHeuristic { Id = 30, PatternType = "string", RiskLevel = "medium", Category = "Упаковщик",         Pattern = "UPX0",                  Description = "Заголовок UPX-упаковщика — исполняемый файл упакован для обфускации" }
        );
    }
}
