package nz.cardforge.desfire;

import java.io.IOException;

/** Common operations for every supported card technology. */
public interface CredentialEncoder {
    Credential encode(Credential cred, boolean overwrite) throws IOException, DesfireException;
    Credential verify() throws IOException, DesfireException;
    void wipe() throws IOException, DesfireException;
}
