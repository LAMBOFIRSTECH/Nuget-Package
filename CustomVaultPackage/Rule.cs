using System.ComponentModel.DataAnnotations;

namespace CustomVaultPackage;

public class Rule
{
    public enum Privilege
    {
        Administrateur,
        Manager,
    }

    [EnumDataType(typeof(Privilege))]
    [Required]
    public Privilege Role { get; set; }
}
