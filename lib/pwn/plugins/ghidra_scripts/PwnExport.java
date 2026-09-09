// Read-only analysis export: never executes the imported program.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.data.DataType;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public class PwnExport extends GhidraScript {
    public void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        JsonObject report = new JsonObject();
        JsonArray functions = new JsonArray();
        JsonArray symbols = new JsonArray();
        JsonArray types = new JsonArray();
        try {
            decompiler.openProgram(currentProgram);
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && !monitor.isCancelled()) {
                Function function = iterator.next();
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                JsonObject row = new JsonObject();
                row.addProperty("name", function.getName());
                row.addProperty("entry", function.getEntryPoint().toString());
                row.addProperty("c", result.decompileCompleted() ? result.getDecompiledFunction().getC() : "");
                row.addProperty("error", result.getErrorMessage());
                functions.add(row);
            }
            SymbolIterator si = currentProgram.getSymbolTable().getAllSymbols(true);
            while (si.hasNext()) {
                Symbol symbol = si.next();
                JsonObject row = new JsonObject();
                row.addProperty("name", symbol.getName());
                row.addProperty("address", symbol.getAddress().toString());
                row.addProperty("type", symbol.getSymbolType().toString());
                symbols.add(row);
            }
            Iterator<DataType> ti = currentProgram.getDataTypeManager().getAllDataTypes();
            while (ti.hasNext()) {
                DataType type = ti.next();
                JsonObject row = new JsonObject();
                row.addProperty("name", type.getPathName());
                row.addProperty("length", type.getLength());
                types.add(row);
            }
            report.add("functions", functions);
            report.add("symbols", symbols);
            report.add("types", types);
            Files.write(Paths.get(getScriptArgs()[0]), report.toString().getBytes(StandardCharsets.UTF_8));
        } finally {
            decompiler.dispose();
        }
    }
}
