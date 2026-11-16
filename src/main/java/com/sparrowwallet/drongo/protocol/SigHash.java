// Modified for Goshawk BitcoinSV, 2026-11-16.
package com.sparrowwallet.drongo.protocol;

import java.util.List;

/**
 * These constants are a part of a scriptSig signature on the inputs. They define the details of how a
 * transaction can be redeemed, specifically, they control how the hash of the transaction is calculated.
 */
public enum SigHash {
    ALL("All", (byte)1),
    NONE("None", (byte)2),
    SINGLE("Single", (byte)3),
    ANYONECANPAY("Anyone Can Pay", (byte)0x80), // Caution: Using this type in isolation is non-standard. Treated similar to ANYONECANPAY_ALL.
    ANYONECANPAY_ALL("All + Anyone Can Pay", (byte)0x81),
    ANYONECANPAY_NONE("None + Anyone Can Pay", (byte)0x82),
    ANYONECANPAY_SINGLE("Single + Anyone Can Pay", (byte)0x83),
    DEFAULT("Default", (byte)0),
    ALL_FORKID("All (ForkID)", (byte)0x41),
    NONE_FORKID("None (ForkID)", (byte)0x42),
    SINGLE_FORKID("Single (ForkID)", (byte)0x43),
    ANYONECANPAY_ALL_FORKID("All + Anyone Can Pay (ForkID)", (byte)0xc1),
    ANYONECANPAY_NONE_FORKID("None + Anyone Can Pay (ForkID)", (byte)0xc2),
    ANYONECANPAY_SINGLE_FORKID("Single + Anyone Can Pay (ForkID)", (byte)0xc3);

    private final String name;
    public final byte value;

    public static final List<SigHash> LEGACY_SIGNING_TYPES = List.of(ALL_FORKID, NONE_FORKID, SINGLE_FORKID, ANYONECANPAY_ALL_FORKID, ANYONECANPAY_NONE_FORKID, ANYONECANPAY_SINGLE_FORKID);
    public static final List<SigHash> TAPROOT_SIGNING_TYPES = List.of(DEFAULT, ALL, NONE, SINGLE, ANYONECANPAY_ALL, ANYONECANPAY_NONE, ANYONECANPAY_SINGLE);

    private SigHash(final String name, final byte value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    /**
     * @return the value as a byte
     */
    public byte byteValue() {
        return this.value;
    }

    public int intValue() {
        return Byte.toUnsignedInt(value);
    }

    public boolean anyoneCanPay() {
        return (value & SigHash.ANYONECANPAY.value) != 0;
    }

    public static SigHash fromByte(byte sigHashByte) {
        for(SigHash value : SigHash.values()) {
            if(sigHashByte == value.byteValue()) {
                return value;
            }
        }

        throw new IllegalArgumentException("No defined sighash value for byte " + sigHashByte);
    }

    @Override
    public String toString() {
        return getName();
    }
}
