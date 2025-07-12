namespace CustomVaultPackage.Middlewares;

public class VaultConfigurationException(int Status, string Type, string message)
    : Exception(message) { }
