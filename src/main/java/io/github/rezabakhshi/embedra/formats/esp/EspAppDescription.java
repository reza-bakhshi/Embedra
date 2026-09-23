package io.github.rezabakhshi.embedra.formats.esp;

import io.github.rezabakhshi.embedra.core.io.SourceRange;
import java.util.Objects;

/** Immutable, source-located metadata decoded from an ESP {@code esp_app_desc_t}. */
public final class EspAppDescription {
    private final long magic;

    private final long secureVersion;

    private final String version;

    private final String projectName;

    private final String buildTime;

    private final String buildDate;

    private final String idfVersion;

    private final byte[] appElfSha256;

    private final int minimumEfuseBlockRevision;

    private final int maximumEfuseBlockRevision;

    private final long mmuPageSizeBytes;

    private final long targetAddress;

    private final SourceRange sourceRange;

    public EspAppDescription(long magic, long secureVersion, String version,
            String projectName, String buildTime, String buildDate, String idfVersion,
            byte[] appElfSha256, int minimumEfuseBlockRevision,
            int maximumEfuseBlockRevision, long mmuPageSizeBytes, long targetAddress,
            SourceRange sourceRange) {
        this.magic = magic;
        this.secureVersion = secureVersion;
        this.version = Objects.requireNonNull(version, "version");
        this.projectName = Objects.requireNonNull(projectName, "projectName");
        this.buildTime = Objects.requireNonNull(buildTime, "buildTime");
        this.buildDate = Objects.requireNonNull(buildDate, "buildDate");
        this.idfVersion = Objects.requireNonNull(idfVersion, "idfVersion");
        this.appElfSha256 = Objects.requireNonNull(appElfSha256,
            "appElfSha256").clone();
        this.minimumEfuseBlockRevision = minimumEfuseBlockRevision;
        this.maximumEfuseBlockRevision = maximumEfuseBlockRevision;
        this.mmuPageSizeBytes = mmuPageSizeBytes;
        this.targetAddress = targetAddress;
        this.sourceRange = Objects.requireNonNull(sourceRange, "sourceRange");
        if (this.appElfSha256.length != 32 || mmuPageSizeBytes <= 0
            || sourceRange.length() != EspAppDescriptionExtractor.DESCRIPTOR_SIZE) {
            throw new IllegalArgumentException("Invalid ESP application description model");
        }
    }

    public long magic() {
        return magic;
    }

    public long secureVersion() {
        return secureVersion;
    }

    public String version() {
        return version;
    }

    public String projectName() {
        return projectName;
    }

    public String buildTime() {
        return buildTime;
    }

    public String buildDate() {
        return buildDate;
    }

    public String idfVersion() {
        return idfVersion;
    }

    public byte[] appElfSha256() {
        return appElfSha256.clone();
    }

    public int minimumEfuseBlockRevision() {
        return minimumEfuseBlockRevision;
    }

    public int maximumEfuseBlockRevision() {
        return maximumEfuseBlockRevision;
    }

    public long mmuPageSizeBytes() {
        return mmuPageSizeBytes;
    }

    public long targetAddress() {
        return targetAddress;
    }

    public SourceRange sourceRange() {
        return sourceRange;
    }
}
