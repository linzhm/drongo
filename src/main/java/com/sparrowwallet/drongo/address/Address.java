// Modified for Goshawk BitcoinSV, 2026-11-16.
package com.sparrowwallet.drongo.address;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.protocol.Base58;
import com.sparrowwallet.drongo.protocol.Bech32;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.ScriptType;

import java.util.Arrays;
import java.util.Locale;

public abstract class Address {
    protected final byte[] data;

    public Address(byte[] data) {
        this.data = data;
    }

    public byte[] getData() {
        return data;
    }

    public String getAddress() {
        return getAddress(Network.get());
    }

    public String getAddress(Network network) {
        return Base58.encodeChecked(getVersion(network), data);
    }

    public String toString() {
        return getAddress(Network.get());
    }

    public String toString(Network network) {
        return getAddress(network);
    }

    public int getVersion() {
        return getVersion(Network.get());
    }

    public abstract int getVersion(Network network);

    public abstract ScriptType getScriptType();

    public Script getOutputScript() {
        return getScriptType().getOutputScript(data);
    }

    public byte[] getOutputScriptData() {
        return data;
    }

    public abstract String getOutputScriptDataType();

    public boolean equals(Object obj) {
        if(!(obj instanceof Address address)) {
            return false;
        }

        return Arrays.equals(data, address.data) && getVersion(Network.get()) == address.getVersion(Network.get()) && getScriptType() == address.getScriptType();
    }

    public int hashCode() {
        return Arrays.hashCode(data) + getVersion(Network.get()) + getScriptType().hashCode();
    }

    public static Address fromString(String address) throws InvalidAddressException {
        try {
            return fromString(Network.get(), address);
        } catch(InvalidAddressException e) {
            for(Network network : Network.canonicalValues()) {
                try {
                    fromString(network, address);
                    if(network != Network.getCanonical()) {
                        throw new InvalidAddressException("Provided " + network.getName() + " address invalid on configured " + Network.getCanonical().getName() + " network: " + address + ". Use a " + network.getName() + " configuration to use this address.");
                    }
                } catch(InvalidAddressException i) {
                    //ignore
                }
            }

            throw e;
        }
    }

    public static Address fromString(Network network, String address) throws InvalidAddressException {
        try {
            byte[] decoded = Base58.decodeChecked(address);
            if(decoded.length == 21 && Byte.toUnsignedInt(decoded[0]) == network.getP2PKHAddressHeader()) {
                return new P2PKHAddress(Arrays.copyOfRange(decoded, 1, 21));
            }
        } catch(Exception e) {
            throw new InvalidAddressException("Invalid BitcoinSV P2PKH address", e);
        }
        throw new InvalidAddressException("Only BitcoinSV P2PKH addresses are supported; use an explicit template for bare multisig");
    }
}
