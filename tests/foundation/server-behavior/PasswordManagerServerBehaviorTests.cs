using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Bit.Api.IntegrationTest.Factories;
using Bit.Api.IntegrationTest.Helpers;
using Bit.Api.Vault.Models;
using Bit.Api.Vault.Models.Request;
using Bit.Api.Vault.Models.Response;
using Bit.Core.AdminConsole.Entities;
using Bit.Core.Billing.Enums;
using Bit.Core.Enums;
using Bit.Core.Models.Data;
using Bit.Core.Repositories;
using Bit.Core.Vault.Enums;
using Bit.Core.Vault.Models.Data;
using Bit.Core.Vault.Repositories;
using Xunit;
using Xunit.Abstractions;

namespace Safeory.Foundation.ServerBehavior;

public sealed class PasswordManagerServerBehaviorTests : IClassFixture<ApiApplicationFactory>, IDisposable
{
    private const string MasterPasswordHash = "master_password_hash";
    private const string EncryptedValue =
        "2.3Uk+WNBIoU5xzmVFNcoWzz==|1MsPIYuRfdOHfu/0uY6H2Q==|/98sp4wb6pHP1VTZ9JcNCYgQjEUMFPlqJgCwRk1YXKg=";
    private static readonly JsonElement CarrierFixture = LoadCarrierFixture();
    private static readonly JsonElement UpdatedCarrierFixture = LoadCarrierFixture(updated: true);
    private static readonly string AttachmentDirectory =
        Path.Combine(Path.GetTempPath(), $"safeory-foundation-attachments-{Guid.NewGuid():N}");
    private static string BlobData =>
        CarrierFixture.GetProperty("data").GetString()
        ?? throw new InvalidOperationException("carrier fixture data is missing");
    private static string BlobKey =>
        CarrierFixture.GetProperty("key").GetString()
        ?? throw new InvalidOperationException("carrier fixture key is missing");
    private static string UpdatedBlobData =>
        UpdatedCarrierFixture.GetProperty("data").GetString()
        ?? throw new InvalidOperationException("updated carrier fixture data is missing");
    private static string UpdatedBlobKey =>
        UpdatedCarrierFixture.GetProperty("key").GetString()
        ?? throw new InvalidOperationException("updated carrier fixture key is missing");

    private readonly ApiApplicationFactory _factory;
    private readonly ITestOutputHelper _output;
    private readonly string _attachmentDirectory = AttachmentDirectory;

    public PasswordManagerServerBehaviorTests(ApiApplicationFactory factory, ITestOutputHelper output)
    {
        _factory = factory;
        _output = output;
        _factory.UpdateConfiguration("globalSettings:attachment:baseDirectory", _attachmentDirectory);
        _factory.UpdateConfiguration("globalSettings:baseServiceUri:api", "http://localhost");
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

        // Personal attachments are a premium upstream capability. Provision entitlement only on
        // this disposable behavior-test account instead of weakening the production server gate.
        var users = _factory.GetService<IUserRepository>();
        var accountAUser = await users.GetByEmailAsync(accountA);
        Assert.NotNull(accountAUser);
        accountAUser.Premium = true;
        accountAUser.MaxStorageGb = 1;
        accountAUser.Storage = 0;
        await users.UpsertAsync(accountAUser);

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

        // Persist opaque attachment bytes through the real local attachment store, then prove a
        // second device can retrieve the signed download while another account cannot.
        var attachmentBytes = Encoding.UTF8.GetBytes("safeory-foundation-opaque-attachment");
        using var attachmentForm = new MultipartFormDataContent();
        attachmentForm.Add(new StringContent(EncryptedValue), "key");
        attachmentForm.Add(new ByteArrayContent(attachmentBytes), "data", "proof.bin");

        var uploadResponse = await deviceA1.PostAsync($"/ciphers/{cipherId}/attachment", attachmentForm);
        if (!uploadResponse.IsSuccessStatusCode)
        {
            var uploadFailure = await uploadResponse.Content.ReadAsStringAsync();
            throw new Xunit.Sdk.XunitException(
                $"attachment upload failed with {(int)uploadResponse.StatusCode} {uploadResponse.StatusCode}: {uploadFailure}");
        }
        using var uploadedCipher = JsonDocument.Parse(await uploadResponse.Content.ReadAsStringAsync());
        var uploadedAttachments = uploadedCipher.RootElement.GetProperty("attachments");
        Assert.Equal(1, uploadedAttachments.GetArrayLength());
        var uploadedAttachment = uploadedAttachments[0];
        var attachmentId = uploadedAttachment.GetProperty("id").GetString();
        Assert.False(string.IsNullOrWhiteSpace(attachmentId));

        using var attachmentMetadataResponse = await deviceA2.GetAsync($"/ciphers/{cipherId}/attachment/{attachmentId}");
        attachmentMetadataResponse.EnsureSuccessStatusCode();
        using var attachmentMetadata = JsonDocument.Parse(await attachmentMetadataResponse.Content.ReadAsStringAsync());
        Assert.Equal("proof.bin", attachmentMetadata.RootElement.GetProperty("fileName").GetString());
        Assert.Equal(EncryptedValue, attachmentMetadata.RootElement.GetProperty("key").GetString());

        var downloadUrl = attachmentMetadata.RootElement.GetProperty("url").GetString();
        Assert.False(string.IsNullOrWhiteSpace(downloadUrl));
        using var downloadResponse = await deviceA2.GetAsync(downloadUrl);
        downloadResponse.EnsureSuccessStatusCode();
        Assert.Equal(attachmentBytes, await downloadResponse.Content.ReadAsByteArrayAsync());

        using var otherAccountAttachment = await accountBClient.GetAsync($"/ciphers/{cipherId}/attachment/{attachmentId}");
        Assert.Equal(HttpStatusCode.NotFound, otherAccountAttachment.StatusCode);

        using var deleteAttachmentResponse = await deviceA1.DeleteAsync($"/ciphers/{cipherId}/attachment/{attachmentId}");
        deleteAttachmentResponse.EnsureSuccessStatusCode();

        using var deletedAttachmentMetadata = await deviceA2.GetAsync($"/ciphers/{cipherId}/attachment/{attachmentId}");
        Assert.Equal(HttpStatusCode.NotFound, deletedAttachmentMetadata.StatusCode);

        // Revoke the second device and prove the durable server-side device state changes.
        var devices = _factory.GetService<IDeviceRepository>();
        var deviceA2Record = await devices.GetByIdentifierAsync(deviceA2Identifier, accountAUser.Id);
        Assert.NotNull(deviceA2Record);
        Assert.True(deviceA2Record.Active);

        var deactivateResponse = await deviceA1.DeleteAsync($"/devices/{deviceA2Record.Id}");
        deactivateResponse.EnsureSuccessStatusCode();

        var deactivated = await devices.GetByIdentifierAsync(deviceA2Identifier, accountAUser.Id);
        Assert.NotNull(deactivated);
        Assert.False(deactivated.Active);

        // The Safeory adapter rejects the already-issued JWT for the inactive device without
        // invalidating the still-active first device.
        var revokedTokenProbe = await deviceA2.GetAsync("/sync");
        Assert.Equal(HttpStatusCode.Unauthorized, revokedTokenProbe.StatusCode);

        var activeDeviceProbe = await deviceA1.GetAsync("/sync");
        activeDeviceProbe.EnsureSuccessStatusCode();
        _output.WriteLine(
            "post-deactivation status: revoked={0}, active={1}",
            (int)revokedTokenProbe.StatusCode,
            (int)activeDeviceProbe.StatusCode);
    }

    [Fact]
    public async Task BlobCipherSyncsAndCannotBeSilentlyDowngraded()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var email = $"safeory-blob-{suffix}@example.com";
        await _factory.LoginWithNewAccount(email, MasterPasswordHash);

        var users = _factory.GetService<IUserRepository>();
        var user = await users.GetByEmailAsync(email);
        Assert.NotNull(user);
        user.Premium = true;
        user.MaxStorageGb = 1;
        user.Storage = 0;
        await users.UpsertAsync(user);

        var device1Tokens = await _factory.Identity.TokenFromPasswordAsync(
            email,
            MasterPasswordHash,
            $"safeory-blob-a1-{suffix}",
            deviceType: DeviceType.FirefoxBrowser,
            deviceName: "safeory-blob-firefox");
        var device2Tokens = await _factory.Identity.TokenFromPasswordAsync(
            email,
            MasterPasswordHash,
            $"safeory-blob-a2-{suffix}",
            deviceType: DeviceType.ChromeBrowser,
            deviceName: "safeory-blob-chromium");

        using var device1 = _factory.CreateAuthedClient(device1Tokens.Token);
        using var device2 = _factory.CreateAuthedClient(device2Tokens.Token);

        var createResponse = await device1.PostAsJsonAsync("/ciphers", BlobRequest());
        createResponse.EnsureSuccessStatusCode();
        using var created = JsonDocument.Parse(await createResponse.Content.ReadAsStringAsync());
        var cipherId = created.RootElement.GetProperty("id").GetGuid();
        var createdRevision = created.RootElement.GetProperty("revisionDate").GetDateTime();
        Assert.Equal(BlobData, created.RootElement.GetProperty("data").GetString());
        Assert.Equal(BlobKey, created.RootElement.GetProperty("key").GetString());
        Assert.True(
            !created.RootElement.TryGetProperty("name", out var createdName) ||
            createdName.ValueKind == JsonValueKind.Null);

        var secondDeviceSync = await Sync(device2);
        var synced = FindCipher(secondDeviceSync.RootElement, cipherId);
        Assert.Equal(BlobData, synced.GetProperty("data").GetString());
        Assert.Equal(BlobKey, synced.GetProperty("key").GetString());

        var blobUpdate = await device1.PutAsJsonAsync(
            $"/ciphers/{cipherId}",
            UpdatedBlobRequest(createdRevision, favorite: true));
        blobUpdate.EnsureSuccessStatusCode();
        using var updated = JsonDocument.Parse(await blobUpdate.Content.ReadAsStringAsync());
        var updatedRevision = updated.RootElement.GetProperty("revisionDate").GetDateTime();
        Assert.True(updatedRevision >= createdRevision);
        Assert.True(updated.RootElement.GetProperty("favorite").GetBoolean());
        Assert.NotEqual(BlobData, UpdatedBlobData);
        Assert.NotEqual(BlobKey, UpdatedBlobKey);
        Assert.Equal(UpdatedBlobData, updated.RootElement.GetProperty("data").GetString());
        Assert.Equal(UpdatedBlobKey, updated.RootElement.GetProperty("key").GetString());

        var secondDeviceAfterUpdate = await Sync(device2);
        var syncedUpdate = FindCipher(secondDeviceAfterUpdate.RootElement, cipherId);
        Assert.Equal(UpdatedBlobData, syncedUpdate.GetProperty("data").GetString());
        Assert.Equal(UpdatedBlobKey, syncedUpdate.GetProperty("key").GetString());
        Assert.True(syncedUpdate.GetProperty("favorite").GetBoolean());

        var downgrade = await device1.PutAsJsonAsync(
            $"/ciphers/{cipherId}",
            LegacySecureNoteRequest(updatedRevision));
        Assert.Equal(HttpStatusCode.BadRequest, downgrade.StatusCode);
        var downgradeBody = await downgrade.Content.ReadAsStringAsync();
        Assert.Contains("Cannot overwrite a blob-encrypted item", downgradeBody);

        var afterRejectedDowngrade = await Sync(device2);
        var preserved = FindCipher(afterRejectedDowngrade.RootElement, cipherId);
        Assert.Equal(UpdatedBlobData, preserved.GetProperty("data").GetString());
        Assert.Equal(UpdatedBlobKey, preserved.GetProperty("key").GetString());
        Assert.True(preserved.GetProperty("favorite").GetBoolean());

        // Exercise the complete attachment lifecycle on the selected Safeory blob carrier:
        // upload, second-device download, encrypted metadata rename, re-download, and delete.
        var attachmentBytes = Encoding.UTF8.GetBytes("safeory-blob-carrier-opaque-attachment");
        using var attachmentForm = new MultipartFormDataContent();
        attachmentForm.Add(new StringContent(EncryptedValue), "key");
        attachmentForm.Add(new ByteArrayContent(attachmentBytes), "data", "proof.bin");

        var uploadResponse = await device1.PostAsync($"/ciphers/{cipherId}/attachment", attachmentForm);
        uploadResponse.EnsureSuccessStatusCode();
        using var uploadedCipher = JsonDocument.Parse(await uploadResponse.Content.ReadAsStringAsync());
        var uploadedRevision = uploadedCipher.RootElement.GetProperty("revisionDate").GetDateTime();
        var uploadedAttachment = uploadedCipher.RootElement.GetProperty("attachments")[0];
        var attachmentId = uploadedAttachment.GetProperty("id").GetString();
        Assert.False(string.IsNullOrWhiteSpace(attachmentId));

        using var initialMetadataResponse = await device2.GetAsync($"/ciphers/{cipherId}/attachment/{attachmentId}");
        initialMetadataResponse.EnsureSuccessStatusCode();
        using var initialMetadata = JsonDocument.Parse(await initialMetadataResponse.Content.ReadAsStringAsync());
        var initialDownloadUrl = initialMetadata.RootElement.GetProperty("url").GetString();
        Assert.False(string.IsNullOrWhiteSpace(initialDownloadUrl));
        using var initialDownload = await device2.GetAsync(initialDownloadUrl);
        initialDownload.EnsureSuccessStatusCode();
        Assert.Equal(attachmentBytes, await initialDownload.Content.ReadAsByteArrayAsync());

        var corruptedRenameRequest = UpdatedBlobRequest(uploadedRevision, favorite: true);
        corruptedRenameRequest.Attachments2 = new Dictionary<string, CipherAttachmentModel>
        {
            [attachmentId!] = new CipherAttachmentModel
            {
                FileName = "plain-text-file-name",
                Key = EncryptedValue,
            },
        };
        var corruptedRenameResponse =
            await device1.PutAsJsonAsync($"/ciphers/{cipherId}", corruptedRenameRequest);
        Assert.Equal(HttpStatusCode.BadRequest, corruptedRenameResponse.StatusCode);

        using var metadataAfterCorruptRename =
            await device2.GetAsync($"/ciphers/{cipherId}/attachment/{attachmentId}");
        metadataAfterCorruptRename.EnsureSuccessStatusCode();
        using var unchangedMetadata =
            JsonDocument.Parse(await metadataAfterCorruptRename.Content.ReadAsStringAsync());
        Assert.Equal("proof.bin", unchangedMetadata.RootElement.GetProperty("fileName").GetString());

        var renameRequest = UpdatedBlobRequest(uploadedRevision, favorite: true);
        renameRequest.Attachments2 = new Dictionary<string, CipherAttachmentModel>
        {
            [attachmentId!] = new CipherAttachmentModel
            {
                FileName = EncryptedValue,
                Key = EncryptedValue,
            },
        };
        var renameResponse = await device1.PutAsJsonAsync($"/ciphers/{cipherId}", renameRequest);
        renameResponse.EnsureSuccessStatusCode();
        using var renamedCipher = JsonDocument.Parse(await renameResponse.Content.ReadAsStringAsync());
        Assert.Equal(EncryptedValue,
            renamedCipher.RootElement.GetProperty("attachments")[0].GetProperty("fileName").GetString());

        using var renamedMetadataResponse = await device2.GetAsync($"/ciphers/{cipherId}/attachment/{attachmentId}");
        renamedMetadataResponse.EnsureSuccessStatusCode();
        using var renamedMetadata = JsonDocument.Parse(await renamedMetadataResponse.Content.ReadAsStringAsync());
        Assert.Equal(EncryptedValue, renamedMetadata.RootElement.GetProperty("fileName").GetString());
        var renamedDownloadUrl = renamedMetadata.RootElement.GetProperty("url").GetString();
        Assert.False(string.IsNullOrWhiteSpace(renamedDownloadUrl));
        using var renamedDownload = await device2.GetAsync(renamedDownloadUrl);
        renamedDownload.EnsureSuccessStatusCode();
        Assert.Equal(attachmentBytes, await renamedDownload.Content.ReadAsByteArrayAsync());

        var secondDeviceAfterRename = await Sync(device2);
        var carrierAfterRename = FindCipher(secondDeviceAfterRename.RootElement, cipherId);
        Assert.Equal(EncryptedValue,
            carrierAfterRename.GetProperty("attachments")[0].GetProperty("fileName").GetString());
        Assert.Equal(UpdatedBlobData, carrierAfterRename.GetProperty("data").GetString());
        Assert.Equal(UpdatedBlobKey, carrierAfterRename.GetProperty("key").GetString());

        using var deleteAttachment = await device1.DeleteAsync($"/ciphers/{cipherId}/attachment/{attachmentId}");
        deleteAttachment.EnsureSuccessStatusCode();

        using var deletedMetadata = await device2.GetAsync($"/ciphers/{cipherId}/attachment/{attachmentId}");
        Assert.Equal(HttpStatusCode.NotFound, deletedMetadata.StatusCode);

        var deleteCarrier = await device1.PutAsync($"/ciphers/{cipherId}/delete", null);
        deleteCarrier.EnsureSuccessStatusCode();
        var secondDeviceAfterDelete = await Sync(device2);
        var deletedCarrier = FindCipher(secondDeviceAfterDelete.RootElement, cipherId);
        Assert.NotEqual(JsonValueKind.Null, deletedCarrier.GetProperty("deletedDate").ValueKind);
        Assert.Equal(UpdatedBlobData, deletedCarrier.GetProperty("data").GetString());
        Assert.Equal(UpdatedBlobKey, deletedCarrier.GetProperty("key").GetString());

        var restoreCarrier = await device1.PutAsync($"/ciphers/{cipherId}/restore", null);
        restoreCarrier.EnsureSuccessStatusCode();
        var secondDeviceAfterRestore = await Sync(device2);
        var restoredCarrier = FindCipher(secondDeviceAfterRestore.RootElement, cipherId);
        Assert.True(
            !restoredCarrier.TryGetProperty("deletedDate", out var restoredDeleted) ||
            restoredDeleted.ValueKind == JsonValueKind.Null);
        Assert.Equal(UpdatedBlobData, restoredCarrier.GetProperty("data").GetString());
        Assert.Equal(UpdatedBlobKey, restoredCarrier.GetProperty("key").GetString());
    }

    [Fact]
    public async Task RevokedFamilyMemberStopsReceivingOrganizationKeyAndCipher()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var aliceEmail = $"safeory-space-alice-{suffix}@example.com";
        var bobEmail = $"safeory-space-bob-{suffix}@example.com";
        await _factory.LoginWithNewAccount(aliceEmail, MasterPasswordHash);
        await _factory.LoginWithNewAccount(bobEmail, MasterPasswordHash);

        var userRepository = _factory.GetService<IUserRepository>();
        var alice = await userRepository.GetByEmailAsync(aliceEmail);
        Assert.NotNull(alice);

        // Arrange the sharing boundary directly in persistence. The cloud organization signup
        // command depends on the hosted pricing API, which is deliberately absent from this
        // cleaned self-hosted behavior fixture and is unrelated to Space delivery semantics.
        var organizationRepository = _factory.GetService<IOrganizationRepository>();
        var family = await organizationRepository.CreateAsync(new Organization
        {
            Name = "Safeory Family Space",
            BillingEmail = aliceEmail,
            Plan = "Families",
            PlanType = PlanType.FamiliesAnnually,
            Seats = 6,
            MaxCollections = 50,
            Enabled = true,
            UsePasswordManager = true,
        });

        var organizationUserRepository = _factory.GetService<IOrganizationUserRepository>();
        await organizationUserRepository.CreateAsync(new OrganizationUser
        {
            OrganizationId = family.Id,
            UserId = alice!.Id,
            Key = "family-key-for-alice",
            Status = OrganizationUserStatusType.Confirmed,
            Type = OrganizationUserType.Owner,
        });

        var bobMembership = await OrganizationTestHelpers.CreateUserAsync(
            _factory,
            family.Id,
            bobEmail,
            OrganizationUserType.User);
        bobMembership.Key = "family-key-for-bob";
        await organizationUserRepository.ReplaceAsync(bobMembership);

        var familyCollection = await OrganizationTestHelpers.CreateCollectionAsync(
            _factory,
            family.Id,
            "Safeory Family records",
            users:
            [
                new CollectionAccessSelection
                {
                    Id = bobMembership.Id,
                    ReadOnly = false,
                    HidePasswords = false,
                    Manage = false,
                },
            ]);

        var familyCipher = new Bit.Core.Vault.Entities.Cipher
        {
            OrganizationId = family.Id,
            Type = CipherType.SecureNote,
            Data = BlobData,
            Key = BlobKey,
            Reprompt = CipherRepromptType.None,
        };
        familyCipher.SetNewId();
        var cipherRepository = _factory.GetService<ICipherRepository>();
        await cipherRepository.CreateAsync(familyCipher, [familyCollection.Id]);

        var bobTokens = await _factory.Identity.TokenFromPasswordAsync(
            bobEmail,
            MasterPasswordHash,
            $"safeory-family-bob-{suffix}",
            deviceType: DeviceType.ChromeBrowser,
            deviceName: "safeory-family-bob");
        using var bobClient = _factory.CreateAuthedClient(bobTokens.Token);

        var beforeRemoval = await Sync(bobClient);
        var deliveredOrganization = FindProfileOrganization(beforeRemoval.RootElement, family.Id);
        Assert.Equal("family-key-for-bob", deliveredOrganization.GetProperty("key").GetString());
        var deliveredCipher = FindCipher(beforeRemoval.RootElement, familyCipher.Id);
        Assert.Equal(BlobData, deliveredCipher.GetProperty("data").GetString());
        Assert.Equal(BlobKey, deliveredCipher.GetProperty("key").GetString());

        await organizationUserRepository.RevokeAsync(bobMembership.Id, RevocationReason.Manual);

        var afterRemoval = await Sync(bobClient);
        Assert.Null(TryFindProfileOrganization(afterRemoval.RootElement, family.Id));
        Assert.Null(TryFindCipher(afterRemoval.RootElement, familyCipher.Id));
    }

    public void Dispose()
    {
        if (Directory.Exists(_attachmentDirectory))
        {
            Directory.Delete(_attachmentDirectory, recursive: true);
        }
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

    private static CipherRequestModel BlobRequest(DateTime? lastKnownRevisionDate = null, bool favorite = false) =>
        new()
        {
            Type = CipherType.SecureNote,
            Favorite = favorite,
            Reprompt = CipherRepromptType.None,
            Data = BlobData,
            Key = BlobKey,
            LastKnownRevisionDate = lastKnownRevisionDate,
        };

    private static CipherRequestModel UpdatedBlobRequest(
        DateTime? lastKnownRevisionDate = null,
        bool favorite = false) =>
        new()
        {
            Type = CipherType.SecureNote,
            Favorite = favorite,
            Reprompt = CipherRepromptType.None,
            Data = UpdatedBlobData,
            Key = UpdatedBlobKey,
            LastKnownRevisionDate = lastKnownRevisionDate,
        };

    private static CipherRequestModel LegacySecureNoteRequest(DateTime lastKnownRevisionDate) =>
        new()
        {
            Type = CipherType.SecureNote,
            Name = EncryptedValue,
            Favorite = true,
            Reprompt = CipherRepromptType.None,
            SecureNote = new CipherSecureNoteModel
            {
                Type = SecureNoteType.Generic,
            },
            LastKnownRevisionDate = lastKnownRevisionDate,
        };

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

    private static JsonElement FindProfileOrganization(JsonElement sync, Guid id) =>
        TryFindProfileOrganization(sync, id)
        ?? throw new Xunit.Sdk.XunitException($"organization {id} was missing from sync profile");

    private static JsonElement? TryFindProfileOrganization(JsonElement sync, Guid id)
    {
        if (!sync.TryGetProperty("profile", out var profile) ||
            !profile.TryGetProperty("organizations", out var organizations) ||
            organizations.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var organization in organizations.EnumerateArray())
        {
            if (organization.GetProperty("id").GetGuid() == id)
            {
                return organization.Clone();
            }
        }

        return null;
    }

    private static JsonElement LoadCarrierFixture(bool updated = false)
    {
        var fileName = updated
            ? "safeory-insurance-carrier-updated.json"
            : "safeory-insurance-carrier.json";
        var fixturePath = Path.Combine(AppContext.BaseDirectory, "fixtures", fileName);
        using var document = JsonDocument.Parse(File.ReadAllText(fixturePath));
        return document.RootElement.Clone();
    }
}
