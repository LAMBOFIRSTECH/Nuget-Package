namespace JwtAuthLibrary.Middleware;

public class VaultConfigurationException(int Status, string Type, string message) : Exception(message)
{
}