import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import java.io.*;
import java.nio.file.*;

public class ResultOutput {
    private JSONArray results;
    private String osName;
    private String outputPath;

    public ResultOutput(String osName) {
        this.osName = osName;
        this.results = new JSONArray();
        this.outputPath = osName.equals("Windows")
            ? "C:\\Users\\Administrator\\Desktop\\Project\\concept-eval.json"
            : "/tmp/clv/concept-eval.json";
    }

    public void init() {
        try {
            File file = new File(outputPath);
            file.getParentFile().mkdirs();
            if (!file.exists()) Files.writeString(file.toPath(), "[]");
        } catch (IOException e) {
            System.err.println("Error initializing output file: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    public void updateResult(int status, String description, String actualResult,
            String expectedResult, String statusText, String output, String marks) {
        JSONObject result = new JSONObject();
        result.put("status", status);
        result.put("description", description);
        result.put("actualResult", actualResult);
        result.put("expectedResult", expectedResult);
        result.put("statusText", statusText);
        result.put("output", output);
        result.put("marks", marks);
        results.add(result);
        System.out.println("[" + statusText + "] " + description + " - Marks: " + marks);
    }

    public void updateJSON() {
        try {
            Files.writeString(Path.of(outputPath), results.toJSONString());
            System.out.println("Results written to: " + outputPath);
        } catch (IOException e) {
            System.err.println("Error writing results: " + e.getMessage());
        }
    }
}
