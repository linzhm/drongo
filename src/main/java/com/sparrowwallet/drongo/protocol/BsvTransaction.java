/* Copyright 2026 Goshawk contributors. Licensed under the Apache License, Version 2.0. */
package com.sparrowwallet.drongo.protocol;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.wallet.Wallet;

import java.io.ByteArrayOutputStream;
import java.util.Set;

/** Goshawk's deliberately small transaction policy. This is not a consensus script interpreter. */
public final class BsvTransaction {
    public static final Set<Integer> SIGHASHES = Set.of(0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3);
    private BsvTransaction() {}

    public static void requireWallet(Wallet wallet) {
        if(wallet.getPolicyType() != PolicyType.SINGLE_HD || wallet.getScriptType() != ScriptType.P2PKH) {
            throw new IllegalArgumentException("Goshawk address wallets require BitcoinSV P2PKH. Bare multisig uses explicit transaction templates.");
        }
    }

    public static void requireSigningScript(Script script) {
        if(script == null || (!ScriptType.P2PKH.isScriptType(script) && !ScriptType.MULTISIG.isScriptType(script))) {
            throw new IllegalArgumentException("BitcoinSV signing supports P2PKH and bare multisig only; P2SH and witness templates are not supported");
        }
    }

    public static void requireOutput(Script script) {
        byte[] bytes = script.getProgram();
        boolean data = bytes.length > 0 && (bytes[0] == 0x6a || (bytes.length > 1 && bytes[0] == 0 && bytes[1] == 0x6a));
        if(!data) requireSigningScript(script);
    }

    public static void requireTransaction(Transaction tx) {
        if(tx.isSegwit() || tx.hasWitnesses()) throw new IllegalArgumentException("BitcoinSV requires ordinary transaction serialization");
        uint32(tx.getVersion()); uint32(tx.getLocktime());
        tx.getInputs().forEach(input -> { uint32(input.getSequenceNumber()); uint32(input.getOutpoint().getIndex()); });
        tx.getOutputs().forEach(output -> {
            if(output.getValue() < 0 || output.getValue() > Transaction.MAX_SATOSHIS) throw new IllegalArgumentException("Invalid output amount");
            requireOutput(output.getScript());
        });
    }

    /** PSBT is retained as an internal UI data container, never as a Bitcoin signing route. */
    public static void requireContainer(PSBT psbt) {
        requireTransaction(psbt.getTransaction());
        for(PSBTInput input : psbt.getPsbtInputs()) {
            if(input.getWitnessUtxo() != null || input.getWitnessScript() != null || input.getRedeemScript() != null ||
                    input.getFinalScriptWitness() != null || input.getTapInternalKey() != null ||
                    input.getTapKeyPathSignature() != null || !input.getTapDerivedPublicKeys().isEmpty() || input.getSilentPaymentsTweak() != null) {
                throw new IllegalArgumentException("P2SH, SegWit, Taproot and silent-payment fields are not accepted by BitcoinSV");
            }
            if(input.getNonWitnessUtxo() != null) {
                Transaction parent = input.getNonWitnessUtxo();
                if(parent.isSegwit() || parent.hasWitnesses() || !parent.getTxId().equals(input.getInput().getOutpoint().getHash()) || input.getUtxo() == null) {
                    throw new IllegalArgumentException("Previous transaction does not match the input outpoint");
                }
            }
            if(input.getUtxo() != null) requireSigningScript(input.getUtxo().getScript());
            if(input.getSigHash() != null) requireSigHash(input.getSigHash().intValue());
            input.getSignatures().forEach(sig -> requireSigHash(Byte.toUnsignedInt(sig.sighashFlags)));
        }
        if(psbt.getPsbtOutputs().stream().anyMatch(out -> out.getSilentPaymentAddress() != null || out.getRedeemScript() != null || out.getWitnessScript() != null || out.getTapInternalKey() != null || !out.getTapDerivedPublicKeys().isEmpty())) {
            throw new IllegalArgumentException("Silent payments are not supported by BitcoinSV");
        }
    }

    /** ForkID zero preimage, committing to the spent amount, with no witness serialization or flags. */
    public static Sha256Hash signatureHash(Transaction tx, int index, Script script, long amount, int sighash) {
        requireTransaction(tx); requireSigningScript(script); requireSigHash(sighash);
        if(index < 0 || index >= tx.getInputs().size() || amount < 0 || amount > Transaction.MAX_SATOSHIS) throw new IllegalArgumentException("Invalid signing input");
        int mode = sighash & 0x1f;
        if(mode == 3 && index >= tx.getOutputs().size()) throw new IllegalArgumentException("SINGLE requires a corresponding output");
        boolean anyone = (sighash & 0x80) != 0;
        ByteArrayOutputStream prevouts = new ByteArrayOutputStream(), sequences = new ByteArrayOutputStream(), outputs = new ByteArrayOutputStream();
        tx.getInputs().forEach(in -> { prevouts.writeBytes(in.getOutpoint().bitcoinSerialize()); sequences.writeBytes(u32(in.getSequenceNumber())); });
        if(mode == 1) tx.getOutputs().forEach(out -> outputs.writeBytes(out.bitcoinSerialize()));
        else if(mode == 3) outputs.writeBytes(tx.getOutputs().get(index).bitcoinSerialize());
        ByteArrayOutputStream preimage = new ByteArrayOutputStream();
        preimage.writeBytes(u32(tx.getVersion()));
        preimage.writeBytes(anyone ? new byte[32] : Sha256Hash.hashTwice(prevouts.toByteArray()));
        preimage.writeBytes(anyone || mode != 1 ? new byte[32] : Sha256Hash.hashTwice(sequences.toByteArray()));
        preimage.writeBytes(tx.getInputs().get(index).getOutpoint().bitcoinSerialize());
        byte[] scriptBytes = script.getProgram();
        preimage.writeBytes(new VarInt(scriptBytes.length).encode()); preimage.writeBytes(scriptBytes);
        byte[] value = new byte[8]; Utils.int64ToByteArrayLE(amount, value, 0); preimage.writeBytes(value);
        preimage.writeBytes(u32(tx.getInputs().get(index).getSequenceNumber()));
        preimage.writeBytes(mode == 2 ? new byte[32] : Sha256Hash.hashTwice(outputs.toByteArray()));
        preimage.writeBytes(u32(tx.getLocktime())); preimage.writeBytes(u32(sighash));
        return Sha256Hash.twiceOf(preimage.toByteArray());
    }

    public static void requireSigHash(int sighash) {
        if(!SIGHASHES.contains(sighash)) throw new IllegalArgumentException("BitcoinSV requires a ForkID signature (default 0x41)");
    }
    private static byte[] u32(long value) { uint32(value); byte[] bytes = new byte[4]; Utils.uint32ToByteArrayLE(value, bytes, 0); return bytes; }
    private static void uint32(long value) { if(value < 0 || value > 0xffffffffL) throw new IllegalArgumentException("Transaction field exceeds uint32"); }
}
