using FluentValidation;
using NetworkThreats.Models;

namespace NetworkThreats.Validators;

/// <summary>
/// Правила валидации формы создания и редактирования угрозы.
/// </summary>
public class ThreatValidator : AbstractValidator<Threat>
{
    /// <summary>Инициализирует набор правил валидации для <see cref="Threat"/>.</summary>
    public ThreatValidator()
    {
        RuleFor(t => t.Name)
            .NotEmpty().WithMessage("Название обязательно")
            .MinimumLength(2).WithMessage("Название не менее 2 символов")
            .MaximumLength(150).WithMessage("Название не более 150 символов");

        RuleFor(t => t.CategoryId)
            .GreaterThan(0).WithMessage("Выберите категорию");

        RuleFor(t => t.ShortDescription)
            .NotEmpty().WithMessage("Описание обязательно")
            .MinimumLength(10).WithMessage("Описание не менее 10 символов")
            .MaximumLength(2000).WithMessage("Описание не более 2000 символов");

        RuleFor(t => t.Severity)
            .NotEmpty()
            .Must(s => new[] { "low", "medium", "high", "critical" }.Contains(s))
            .WithMessage("Выберите корректный уровень угрозы");

        RuleFor(t => t.AttackVector)
            .MaximumLength(500).WithMessage("Вектор атаки не более 500 символов")
            .When(t => !string.IsNullOrEmpty(t.AttackVector));

        RuleFor(t => t.FirstDetectedYear)
            .InclusiveBetween(1970, DateTime.Now.Year)
            .WithMessage($"Год должен быть от 1970 до {DateTime.Now.Year}")
            .When(t => t.FirstDetectedYear.HasValue);
    }
}
