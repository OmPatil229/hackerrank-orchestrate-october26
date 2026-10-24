/**
 * src/modules/llmClient.js
 *
 * Unified LLM client that wraps Google Gemini (primary) and
 * Anthropic Claude (fallback). Provides structured JSON responses.
 */

import 'dotenv/config';

let _client = null;

class GeminiClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.modelName = 'gemini-2.0-flash';
  }

  async classify(prompt) {
    const { GoogleGenerativeAI } = await import('@google/generative-ai');
    const genai = new GoogleGenerativeAI(this.apiKey);
    const model = genai.getGenerativeModel({
      model: this.modelName,
      generationConfig: { responseMimeType: 'application/json' },
    });
    const result = await model.generateContent(prompt);
    return result.response.text();
  }

  async extract(prompt) {
    const { GoogleGenerativeAI } = await import('@google/generative-ai');
    const genai = new GoogleGenerativeAI(this.apiKey);
    const model = genai.getGenerativeModel({
      model: this.modelName,
      generationConfig: { responseMimeType: 'application/json' },
    });
    const result = await model.generateContent(prompt);
    return result.response.text();
  }

  async extractFromImage(base64Data, mimeType, prompt) {
    const { GoogleGenerativeAI } = await import('@google/generative-ai');
    const genai = new GoogleGenerativeAI(this.apiKey);
    const model = genai.getGenerativeModel({
      model: this.modelName,
      generationConfig: { responseMimeType: 'application/json' },
    });
    const result = await model.generateContent([
      { inlineData: { data: base64Data, mimeType } },
      prompt,
    ]);
    return result.response.text();
  }
}

class AnthropicClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
  }

  async classify(prompt) {
    const Anthropic = (await import('@anthropic-ai/sdk')).default;
    const client = new Anthropic({ apiKey: this.apiKey });
    const msg = await client.messages.create({
      model: 'claude-sonnet-4-5',
      max_tokens: 128,
      messages: [{ role: 'user', content: prompt }],
    });
    return msg.content[0].text;
  }

  async extract(prompt) {
    const Anthropic = (await import('@anthropic-ai/sdk')).default;
    const client = new Anthropic({ apiKey: this.apiKey });
    const msg = await client.messages.create({
      model: 'claude-sonnet-4-5',
      max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
    });
    return msg.content[0].text;
  }

  async extractFromImage(base64Data, mimeType, prompt) {
    const Anthropic = (await import('@anthropic-ai/sdk')).default;
    const client = new Anthropic({ apiKey: this.apiKey });
    const msg = await client.messages.create({
      model: 'claude-sonnet-4-5',
      max_tokens: 2048,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Data } },
          { type: 'text', text: prompt },
        ],
      }],
    });
    return msg.content[0].text;
  }
}

/** NoOp client for when no API key is available (returns empty JSON) */
class NoopClient {
  async classify() { return '{"is_deletion": true}'; }
  async extract() { return '{"records": []}'; }
  async extractFromImage() { return '{"records": []}'; }
}

export function getLLMClient() {
  if (_client) return _client;

  const geminiKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
  const anthropicKey = process.env.ANTHROPIC_API_KEY;

  if (geminiKey) {
    _client = new GeminiClient(geminiKey);
  } else if (anthropicKey) {
    _client = new AnthropicClient(anthropicKey);
  } else {
    console.warn('[LLMClient] No API key found. Using NoopClient (keyword-only mode).');
    _client = new NoopClient();
  }

  return _client;
}

/** Token usage tracking */
const usage = { calls: 0, inputTokens: 0, outputTokens: 0 };

export function recordUsage(input, output) {
  usage.calls++;
  usage.inputTokens += input;
  usage.outputTokens += output;
}

export function getUsageReport() {
  return { ...usage };
}
