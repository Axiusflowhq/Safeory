using System.Net.Http.Json;
using System.Text.Json;
using Bit.Api.IntegrationTest.Factories;
using Bit.Api.Vault.Models.Request;
using Bit.Api.Vault.Models.Response;
using Bit.Core.Enums;
using Bit.Core.Repositories;
using Bit.Core.Vault.Enums;
using Bit.Core.Vault.Models.Data;
using Xunit;
using Xunit.Abstractions;

namespace Safeory.Foundation.ServerBehavior;

public sealed class PasswordManagerServerBehaviorTests : IClassFixture<ApiApplicationFactory>
{
    private const string MasterPasswordHash = "master_password_hash";
    private const string EncryptedValue =
        "2.3Uk+WNBIoU5xzmVFNcoWzz==|1MsPIYuRfdOHfu/0uY6H2Q==|/98sp4wb6pHP1VTZ9JcNCYgQjEUMFPlqJgCwRk1YXKg=";

    private readonly ApiApplicationFactory _factory;
    private readonly ITestOutputHelper _output;

    public PasswordManagerServerBehaviorTests(ApiApplicationFactory factory, ITestOutputHelper output)
    {
        _factory = factory;
        _output = output;
    }

    [Fact]
    public async Task AccountsDevicesAndLoginLifecycleRoundTripThroughCleanedServer()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var accountA = $"safeory-foundation-a-{suffix}@example.com";
        var accountB = $"safeory-foundation-b-{suffix}@example.com";
        var deviceA1Identifier = $"safeory-a1-{suffix}";
        var deviceA2Identifier = $"safeory-a2-{suffix}";

        // Register both accounts through the cleaned server's real Identity/API test host.
        await _factory.LoginWithNewAccount(accountA, MasterPasswordHash);
        var accountBTokens = await _factory.LoginWithNewAccount(accountB, MasterPasswordHash);

        var accountADevice1Tokens = await _factory.Identity.TokenFromPasswordAsync(
            accountA,
            MasterPasswordHash,
            deviceA1Identifier,
            deviceType: DeviceType.FirefoxBrowser,
            deviceName: "safeory-firefox");
        var accountADevice2Tokens = await _factory.Identity.TokenFromPasswordAsync(
            accountA,
            MasterPasswordHash,
            deviceA2Identifier,
            deviceType: DeviceType.ChromeBrowser,
            deviceName: "safeory-chromium");

        Assert.NotEmpty(accountADevice1Tokens.Token);
        Assert.NotEmpty(accountADevice2Tokens.Token);
        Assert.NotEmpty(accountBTokens.Token);

        using var deviceA1 = _factory.CreateAuthedClient(accountADevice1Tokens.Token);
        using var deviceA2 = _factory.CreateAuthedClient(accountADevice2Tokens.Token);
        using var accountBClient = _factory.CreateAuthedClient(accountBTokens.Token);

        // Store a login with username/password/TOTP/URI ciphertext. The server must keep it opaque.
        var createResponse = await deviceA1.PostAsJsonAsync("/ciphers", LoginRequest());
        createResponse.EnsureSuccessStatusCode();
        using var created = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
        var cipherId = created.RootElement.GetProperty("id").GetGuid();
        var createdRevision = created.RootElement.GetProperty("revisionDate").GetDateTime();
        Assert.Equal((int)CipherType.Login, created.RootElement.GetProperty("type").GetInt32());
        Assert.False(created.RootElement.TryGetProperty("deletedDate", out var initialDeleted) &&
                     initialDeleted.ValueKind != JsonValueKind.Null);

        // A distinct device for the same account must receive the same cipher through sync.
        var deviceA2Sync = await Sync(deviceA2);
        var syncedCipher = FindCipher(deviceA2Sync.RootElement, cipherId);
        Assert.Equal(cipherId, syncedCipher.GetProperty("id").GetGuid());
        Assert.False(syncedCipher.TryGetProperty("deletedDate", out var syncedDeleted) &&
                     syncedDeleted.ValueKind != JsonValueKind.Null);

        // A different account must not receive account A's vault item.
        var accountBSync = await Sync(accountBClient);
        Assert.Null(TryFindCipher(accountBSync.RootElement, cipherId));

        // Edit with the server revision fence, then observe the newer revision from device A2.
        var editResponse = await deviceA1.PutAsJsonAsync(
            $"/ciphers/{cipherId}",
            LoginRequest(createdRevision, favorite: true));
        editResponse.EnsureSuccessStatusCode();
        using var edited = JsonDocument.Parse(await editResponse.Content.ReadAsStringAsync());
        var editedRevision = edited.RootElement.GetProperty("revisionDate").GetDateTime();
        Assert.True(editedRevision >= createdRevision);

        var deviceA2AfterEdit = await Sync(deviceA2);
        var editedCipher = FindCipher(deviceA2AfterEdit.RootElement, cipherId);
        Assert.True(editedCipher.GetProperty("favorite").GetBoolean());

        // Soft-delete and restore must propagate through sync without changing identity.
        var deleteResponse = await deviceA1.PutAsync($"/ciphers/{cipherId}/delete", null);
        deleteResponse.EnsureSuccessStatusCode();

        var deviceA2AfterDelete = await Sync(deviceA2);
        var deletedCipher = FindCipher(deviceA2AfterDelete.RootElement, cipherId);
        Assert.NotEqual(JsonValueKind.Null, deletedCipher.GetProperty("deletedDate").ValueKind);

        var restoreResponse = await deviceA1.PutAsync($"/ciphers/{cipherId}/restore", null);
        restoreResponse.EnsureSuccessStatusCode();

        var deviceA2AfterRestore = await Sync(deviceA2);
        var restoredCipher = FindCipher(deviceA2AfterRestore.RootElement, cipherId);
        Assert.True(
            !restoredCipher.TryGetProperty("deletedDate", out var restoredDeleted) ||
            restoredDeleted.ValueKind == JsonValueKind.Null);

        // Revoke the second device and prove the durable server-side device state changes.
        var users = _factory.GetService<IUserRepository>();
        var accountAUser = await users.GetByEmailAsync(accountA);
        Assert.NotNull(accountAUser);

        var devices = _factory.GetService<IDeviceRepository>();
        var deviceA2Record = await devices.GetByIdentifierAsync(deviceA2Identifier, accountAUser.Id);
        Assert.NotNull(deviceA2Record);
        Assert.True(deviceA2Record.Active);

        var deactivateResponse = await deviceA1.DeleteAsync($"/devices/{deviceA2Record.Id}");
        deactivateResponse.EnsureSuccessStatusCode();

        var deactivated = await devices.GetByIdentifierAsync(deviceA2Identifier, accountAUser.Id);
        Assert.NotNull(deactivated);
        Assert.False(deactivated.Active);

        // Probe the existing access token after deactivation. Phase 0.4 does not close its stronger
        // revocation gate until this observed status is explicitly required to be unauthorized/forbidden.
        var revokedTokenProbe = await deviceA2.GetAsync("/sync");
        _output.WriteLine("post-deactivation /sync status: {0}", (int)revokedTokenProbe.StatusCode);
    }

    private static CipherRequestModel LoginRequest(DateTime? lastKnownRevisionDate = null, bool favorite = false)
    {
        var loginData = new CipherLoginData
        {
            Name = EncryptedValue,
            Notes = EncryptedValue,
            Username = EncryptedValue,
            Password = EncryptedValue,
            Totp = EncryptedValue,
            Uris =
            [
                new CipherLoginData.CipherLoginUriData
                {
                    Uri = EncryptedValue,
                    Match = UriMatchType.Domain,
                },
            ],
        };

        return new CipherRequestModel
        {
            Type = CipherType.Login,
            Name = EncryptedValue,
            Favorite = favorite,
            Reprompt = CipherRepromptType.None,
            Data = JsonSerializer.Serialize(loginData),
            LastKnownRevisionDate = lastKnownRevisionDate,
        };
    }

    private static async Task<JsonDocument> Sync(HttpClient client)
    {
        var response = await client.GetAsync("/sync");
        response.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    }

    private static JsonElement FindCipher(JsonElement sync, Guid id) =>
        TryFindCipher(sync, id) ?? throw new Xunit.Sdk.XunitException($"cipher {id} was missing from sync");

    private static JsonElement? TryFindCipher(JsonElement sync, Guid id)
    {
        foreach (var cipher in sync.GetProperty("ciphers").EnumerateArray())
        {
            if (cipher.GetProperty("id").GetGuid() == id)
            {
                return cipher.Clone();
            }
        }

        return null;
    }
}
