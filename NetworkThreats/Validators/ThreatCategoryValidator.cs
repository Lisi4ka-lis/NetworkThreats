using FluentValidation;
using NetworkThreats.Models;

namespace NetworkThreats.Validators;

/// <summary>
/// Правила валидации формы создания категории угроз.
/// </summary>
public class ThreatCategoryValidator : AbstractValidator<ThreatCategory>
{
    /// <summary>Инициализирует набор правил валидации для <see cref="ThreatCategory"/>.</summary>
    public ThreatCategoryValidator()
    {
        RuleFor(c => c.Name)
            .NotEmpty().WithMessage("Название категории обязательно")
            .MinimumLength(2).WithMessage("Название не менее 2 символов")
            .MaximumLength(100).WithMessage("Название не более 100 символов");

        RuleFor(c => c.Description)
            .MaximumLength(500).WithMessage("Описание не более 500 символов")
            .When(c => !string.IsNullOrEmpty(c.Description));
    }
}
