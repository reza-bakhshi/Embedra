package io.github.rezabakhshi.embedra.ghidra.equivalence;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import io.github.rezabakhshi.embedra.analyzers.diff.WorkspaceSnapshot;
import io.github.rezabakhshi.embedra.ghidra.diff.GhidraWorkspaceDiffExtractor;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

/**
 * Reusable test oracle utility for asserting canonical GUI/headless program and snapshot equality.
 */
public final class GhidraProgramEquivalenceAssertor {

    private GhidraProgramEquivalenceAssertor() {
    }

    /**
     * Asserts bit-for-bit, block-for-block, symbol-for-symbol, and option-for-option equivalence
     * between two programs imported under GUI and headless environments.
     *
     * @param gui the program imported under GUI simulation
     * @param headless the program imported under headless simulation
     * @throws Exception on inspection or memory read failure
     */
    public static void assertProgramEquivalence(Program gui, Program headless) throws Exception {
        // 1. Memory blocks equivalence
        MemoryBlock[] guiBlocks = gui.getMemory().getBlocks();
        MemoryBlock[] headlessBlocks = headless.getMemory().getBlocks();
        assertEquals(guiBlocks.length, headlessBlocks.length, "Memory block count must match identically");

        for (int i = 0; i < guiBlocks.length; i++) {
            MemoryBlock g = guiBlocks[i];
            MemoryBlock h = headlessBlocks[i];
            assertEquals(g.getName(), h.getName(), "Block name mismatch at index " + i);
            assertEquals(g.getStart(), h.getStart(), "Block start mismatch for " + g.getName());
            assertEquals(g.getEnd(), h.getEnd(), "Block end mismatch for " + g.getName());
            assertEquals(g.getSize(), h.getSize(), "Block size mismatch for " + g.getName());
            assertEquals(g.isRead(), h.isRead(), "Block read permission mismatch for " + g.getName());
            assertEquals(g.isWrite(), h.isWrite(), "Block write permission mismatch for " + g.getName());
            assertEquals(g.isExecute(), h.isExecute(), "Block execute permission mismatch for " + g.getName());
            assertEquals(g.isVolatile(), h.isVolatile(), "Block volatile mismatch for " + g.getName());
            assertEquals(g.isInitialized(), h.isInitialized(), "Block initialized mismatch for " + g.getName());

            if (g.isInitialized()) {
                byte[] gBytes = new byte[(int) g.getSize()];
                byte[] hBytes = new byte[(int) h.getSize()];
                g.getBytes(g.getStart(), gBytes);
                h.getBytes(h.getStart(), hBytes);
                assertArrayEquals(gBytes, hBytes, "Block byte contents must match byte-for-byte: " + g.getName());
                assertEquals(sha256(gBytes), sha256(hBytes), "Block SHA-256 digest must match: " + g.getName());
            }
        }

        // 2. Symbols equivalence
        List<String> guiSymbols = collectSymbols(gui);
        List<String> headlessSymbols = collectSymbols(headless);
        assertEquals(guiSymbols, headlessSymbols, "Symbols must match symbol-for-symbol identically");

        // 3. External Entry Points
        List<Address> guiEntries = collectEntryPoints(gui);
        List<Address> headlessEntries = collectEntryPoints(headless);
        assertEquals(guiEntries, headlessEntries, "Entry points must match identically");

        // 4. Options categories and properties equivalence
        List<String> guiCategories = gui.getOptionsNames();
        List<String> headlessCategories = headless.getOptionsNames();
        assertEquals(guiCategories, headlessCategories, "Options categories must match");

        for (String cat : guiCategories) {
            var gOpt = gui.getOptions(cat);
            var hOpt = headless.getOptions(cat);
            List<String> gNames = gOpt.getOptionNames();
            List<String> hNames = hOpt.getOptionNames();
            assertEquals(gNames, hNames, "Option names in category '" + cat + "' must match");
            for (String optName : gNames) {
                if (Program.PROGRAM_INFO.equals(cat) && "Date Created".equals(optName)) {
                    continue; // Ghidra built-in timestamp at program instantiation
                }
                assertEquals(gOpt.getObject(optName, null), hOpt.getObject(optName, null),
                        "Option value mismatch for '" + cat + " -> " + optName + "'");
            }
        }

        // 5. Bookmarks equivalence
        List<String> guiBookmarks = collectBookmarks(gui);
        List<String> headlessBookmarks = collectBookmarks(headless);
        assertEquals(guiBookmarks, headlessBookmarks, "Bookmarks must match identically");

        // 6. Comments equivalence across initialized addresses
        AddressSetView initialized = gui.getMemory().getLoadedAndInitializedAddressSet();
        for (Address addr : initialized.getAddresses(true)) {
            for (CommentType type : CommentType.values()) {
                String gComment = gui.getListing().getComment(type, addr);
                String hComment = headless.getListing().getComment(type, addr);
                assertEquals(gComment, hComment, "Comment mismatch (" + type + ") at " + addr);
            }
        }
    }

    /**
     * Asserts that normalized WorkspaceSnapshots extracted from GUI and headless programs are identical.
     *
     * @param gui the program imported under GUI simulation
     * @param headless the program imported under headless simulation
     * @throws Exception on extraction failure
     */
    public static void assertWorkspaceSnapshotEquivalence(Program gui, Program headless) throws Exception {
        GhidraWorkspaceDiffExtractor extractor = new GhidraWorkspaceDiffExtractor();
        WorkspaceSnapshot guiSnap = extractor.extract(gui);
        WorkspaceSnapshot headlessSnap = extractor.extract(headless);

        assertEquals(guiSnap.functions(), headlessSnap.functions(), "Workspace functions must match");
        assertEquals(guiSnap.symbols(), headlessSnap.symbols(), "Workspace symbols must match");
        assertEquals(guiSnap.strings(), headlessSnap.strings(), "Workspace strings must match");
        assertEquals(guiSnap.memoryBlocks(), headlessSnap.memoryBlocks(), "Workspace memory blocks must match");
        assertEquals(guiSnap.partitions(), headlessSnap.partitions(), "Workspace partitions must match");

        var guiMeta = guiSnap.metadata().stream()
                .filter(m -> !"Info.Date Created".equals(m.key()) && !"Program Name".equals(m.key()))
                .toList();
        var headlessMeta = headlessSnap.metadata().stream()
                .filter(m -> !"Info.Date Created".equals(m.key()) && !"Program Name".equals(m.key()))
                .toList();
        assertEquals(guiMeta, headlessMeta, "Workspace metadata must match");
    }

    private static List<String> collectSymbols(Program p) {
        List<String> list = new ArrayList<>();
        SymbolIterator it = p.getSymbolTable().getAllSymbols(false);
        while (it.hasNext()) {
            Symbol s = it.next();
            list.add(s.getName() + "@" + s.getAddress() + "[" + s.getSymbolType() + ",primary=" + s.isPrimary() + "]");
        }
        list.sort(Comparator.naturalOrder());
        return list;
    }

    private static List<Address> collectEntryPoints(Program p) {
        List<Address> list = new ArrayList<>();
        var it = p.getSymbolTable().getExternalEntryPointIterator();
        while (it.hasNext()) {
            list.add(it.next());
        }
        list.sort(Comparator.naturalOrder());
        return list;
    }

    private static List<String> collectBookmarks(Program p) {
        List<String> list = new ArrayList<>();
        var it = p.getBookmarkManager().getBookmarksIterator();
        while (it.hasNext()) {
            Bookmark b = it.next();
            list.add(b.getCategory() + "|" + b.getTypeString() + "@" + b.getAddress() + ":" + b.getComment());
        }
        list.sort(Comparator.naturalOrder());
        return list;
    }

    private static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
