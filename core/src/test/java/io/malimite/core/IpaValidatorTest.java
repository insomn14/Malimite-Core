package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class IpaValidatorTest {

    @Test void rejectsNonExistentFile(@TempDir Path tmp) {
        assertThrows(Exception.class,
                () -> IpaValidator.validate(tmp.resolve("missing.ipa")));
    }

    @Test void rejectsWrongExtension(@TempDir Path tmp) throws Exception {
        Path f = tmp.resolve("app.zip");
        Files.writeString(f, "data");
        assertThrows(Exception.class, () -> IpaValidator.validate(f));
    }

    @Test void rejectsEmptyFile(@TempDir Path tmp) throws Exception {
        Path f = tmp.resolve("empty.ipa");
        Files.createFile(f);
        assertThrows(Exception.class, () -> IpaValidator.validate(f));
    }
}
