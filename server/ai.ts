import { GoogleGenAI, Type } from "@google/genai";

export async function analyzeIntelligenceReport(text: string) {
  const apiKey = process.env.GEMINI_API_KEY;
  
  if (!apiKey || apiKey === "MY_GEMINI_API_KEY") {
    console.log("No valid Gemini API key found, using Demo AI Mode (Deterministic Mock)");
    return generateMockAnalysis(text);
  }

  const ai = new GoogleGenAI({ 
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      }
    }
  });

  try {
    const response = await ai.models.generateContent({
      model: "gemini-3.7-flash",
      contents: `Analyze the following intelligence report and extract threats, entities, and generate a summary.
      Report:
      ${text.substring(0, 50000)}`,
      config: {
        systemInstruction: "You are an expert defense and intelligence analyst. Analyze the provided report and extract key information. Do NOT generate instructions for carrying out attacks, acquiring weapons, evading law enforcement, or causing harm. Classify threats strictly into: LOW, MEDIUM, HIGH, CRITICAL. If no threats are found, return an empty array for threats. If there's no clear evidence, use low confidence.",
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            summary: {
              type: Type.STRING,
              description: "Executive summary of the report."
            },
            threats: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  description: { type: Type.STRING },
                  category: { type: Type.STRING, description: "e.g., Cyber, Infrastructure, Logistics, Suspicious Activity" },
                  severity: { type: Type.STRING, description: "Must be LOW, MEDIUM, HIGH, or CRITICAL" },
                  confidence: { type: Type.INTEGER, description: "0-100" },
                  reasoning: { type: Type.STRING, description: "Why this severity was chosen" },
                  recommendations: { type: Type.ARRAY, items: { type: Type.STRING } }
                },
                required: ["title", "description", "category", "severity", "confidence", "reasoning", "recommendations"]
              }
            },
            entities: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  name: { type: Type.STRING },
                  type: { type: Type.STRING, description: "Location, Organization, Equipment, Person, Event" },
                  confidence: { type: Type.INTEGER }
                },
                required: ["name", "type", "confidence"]
              }
            }
          },
          required: ["summary", "threats", "entities"]
        }
      }
    });

    const parsed = JSON.parse(response.text || "{}");
    return parsed;
  } catch (error) {
    console.error("Gemini API Error, falling back to mock:", error);
    return generateMockAnalysis(text);
  }
}

function generateMockAnalysis(text: string) {
  // Simple heuristic or random generation for demo mode
  return {
    summary: "Mock Executive Summary: The report indicates unusual logistical movements and potential cyber probing activities near critical infrastructure nodes. Confidence remains moderate pending further validation.",
    threats: [
      {
        title: "Suspicious Network Probing",
        description: "Repeated port scanning and failed authentication attempts detected originating from unknown IP ranges.",
        category: "Cyber",
        severity: text.length % 2 === 0 ? "HIGH" : "MEDIUM",
        confidence: 85,
        reasoning: "Multiple related indicators of network mapping, suggesting pre-attack reconnaissance.",
        recommendations: ["Increase firewall logging", "Isolate affected subnet", "Notify cyber incident response team"]
      },
      {
         title: "Unauthorized Drone Activity",
         description: "Sightings of commercial drones hovering near the perimeter of Facility B.",
         category: "Physical Security",
         severity: "LOW",
         confidence: 60,
         reasoning: "Isolated incident but poses a potential intelligence gathering threat.",
         recommendations: ["Increase perimeter patrols", "Review anti-drone countermeasures"]
      }
    ],
    entities: [
      { name: "Sector 7G", type: "Location", confidence: 90 },
      { name: "Unknown Actor Alpha", type: "Person", confidence: 50 },
      { name: "Logistics Hub C", type: "Organization", confidence: 95 }
    ]
  };
}
