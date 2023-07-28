package cj.geochat.util.minio;

public enum MinioQuotaUnit {
    KB(1024L),
    MB(1024L * KB.unit),
    GB(1024L * MB.unit),
    TB(1024L * GB.unit);

    private final long unit;

    private MinioQuotaUnit(long unit) {
        this.unit = unit;
    }

    public long toBytes(long size) {
        long totalSize = size * this.unit;
        if (totalSize < 0L) {
            throw new IllegalArgumentException("Quota size must be greater than zero.But actual is " + totalSize);
        } else if (totalSize / this.unit != size) {
            throw new IllegalArgumentException("Quota size overflow");
        } else {
            return totalSize;
        }
    }
}