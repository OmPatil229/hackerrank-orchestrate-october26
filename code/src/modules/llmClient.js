/**
 * src/modules/llmClient.js
 *
 * Unified LLM client supporting:
 *  1. NVIDIA NIM API (via standard OpenAI-compatible API)
 *  2. Google Gemini
 *  3. Anthropic Claude
 *  4. NoopClient (fallback when no API key is provided)
 */

import 'dotenv/config';

let _client = null;

/** Token usage tracking */
const usage = {
  model: 'unknown',
  calls: 0,
  inputTokens: 0,
  outputTokens: 0,
};

export function recordUsage(input, output, modelName) {
  usage.calls++;
  usage.inputTokens += (input || 0);
  usage.outputTokens += (output || 0);
  if (modelName) usage.model = modelName;
}

export function getUsageReport() {
  return { ...usage };
}

/**
 * NVIDIA NIM Client
 * Uses OpenAI-compatible endpoints at https://integrate.api.nvidia.com/v1
 */
class NvidiaClient {
  constructor(apiKey, textModel = 'meta/llama-3.3-70b-instruct', visionModel = 'meta/llama-3.2-90b-vision-instruct') {
    this.apiKey = apiKey;
    this.baseUrl = process.env.NVIDIA_BASE_URL || 'https://integrate.api.nvidia.com/v1';
    this.textModel = process.env.NVIDIA_MODEL || textModel;
    this.visionModel = process.env.NVIDIA_VISION_MODEL || visionModel;
  }

  async _chat(messages, model, maxTokens = 1024, responseFormat = null) {
    const payload = {
      model,
      messages,
      temperature: 0.1,
      top_p: 0.7,
      max_tokens: maxTokens,
    };
    if (responseFormat) {
      payload.response_format = responseFormat;
    }

    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`NVIDIA API error (${res.status}): ${errText}`);
    }

    const data = await res.json();
    if (data.usage) {
      recordUsage(data.usage.prompt_tokens, data.usage.completion_tokens, model);
    }
    return data.choices?.[0]?.message?.content || '';
  }

  async classify(prompt) {
    return this._chat(
      [{ role: 'user', content: prompt }],
      this.textModel,
      256
    );
  }

  async extract(prompt) {
    return this._chat(
      [{ role: 'user', content: prompt }],
      this.textModel,
      2048
    );
  }

  async extractFromImage(base64Data, mimeType, prompt) {
    const messages = [
      {
        role: 'user',
        content: [
          { type: 'text', text: prompt },
          {
            type: 'image_url',
            image_url: {
              url: `data:${mimeType};base64,${base64Data}`,
            },
          },
        ],
      },
    ];
    return this._chat(messages, this.visionModel, 2048);
  }
}

class GeminiClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.modelName = process.env.GEMINI_MODEL || 'gemini-2.0-flash';
  }

  async classify(prompt) {
    const { GoogleGenerativeAI } = await import('@google/generative-ai');
    const genai = new GoogleGenerativeAI(this.apiKey);
    const model = genai.getGenerativeModel({
      model: this.modelName,
      generationConfig: { responseMimeType: 'application/json' },
    });
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    recordUsage(200, 50, this.modelName);
    return text;
  }

  async extract(prompt) {
    const { GoogleGenerativeAI } = await import('@google/generative-ai');
    const genai = new GoogleGenerativeAI(this.apiKey);
    const model = genai.getGenerativeModel({
      model: this.modelName,
      generationConfig: { responseMimeType: 'application/json' },
    });
    const result = await model.generateContent(prompt);
    const text = result.response.text();
    recordUsage(1500, 300, this.modelName);
    return text;
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
    const text = result.response.text();
    recordUsage(2000, 400, this.modelName);
    return text;
  }
}

class AnthropicClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.modelName = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5';
  }

  async classify(prompt) {
    const Anthropic = (await import('@anthropic-ai/sdk')).default;
    const client = new Anthropic({ apiKey: this.apiKey });
    const msg = await client.messages.create({
      model: this.modelName,
      max_tokens: 128,
      messages: [{ role: 'user', content: prompt }],
    });
    recordUsage(msg.usage?.input_tokens, msg.usage?.output_tokens, this.modelName);
    return msg.content[0].text;
  }

  async extract(prompt) {
    const Anthropic = (await import('@anthropic-ai/sdk')).default;
    const client = new Anthropic({ apiKey: this.apiKey });
    const msg = await client.messages.create({
      model: this.modelName,
      max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
    });
    recordUsage(msg.usage?.input_tokens, msg.usage?.output_tokens, this.modelName);
    return msg.content[0].text;
  }

  async extractFromImage(base64Data, mimeType, prompt) {
    const Anthropic = (await import('@anthropic-ai/sdk')).default;
    const client = new Anthropic({ apiKey: this.apiKey });
    const msg = await client.messages.create({
      model: this.modelName,
      max_tokens: 2048,
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Data } },
          { type: 'text', text: prompt },
        ],
      }],
    });
    recordUsage(msg.usage?.input_tokens, msg.usage?.output_tokens, this.modelName);
    return msg.content[0].text;
  }
}

/** NoOp client for when no API key is available */
class NoopClient {
  async classify() { return '{"is_deletion": true}'; }
  async extract() { return '{"records": []}'; }
  async extractFromImage() { return '{"records": []}'; }
}

export function getLLMClient() {
  if (_client) return _client;

  const nvidiaKey = process.env.NVIDIA_API_KEY;
  const geminiKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
  const anthropicKey = process.env.ANTHROPIC_API_KEY;

  if (nvidiaKey) {
    console.log('[LLMClient] Using NVIDIA NIM Client (models: ' +
      (process.env.NVIDIA_MODEL || 'meta/llama-3.3-70b-instruct') + ' / ' +
      (process.env.NVIDIA_VISION_MODEL || 'meta/llama-3.2-90b-vision-instruct') + ')');
    _client = new NvidiaClient(nvidiaKey);
  } else if (geminiKey) {
    console.log('[LLMClient] Using Gemini Client (' + (process.env.GEMINI_MODEL || 'gemini-2.0-flash') + ')');
    _client = new GeminiClient(geminiKey);
  } else if (anthropicKey) {
    console.log('[LLMClient] Using Anthropic Client (' + (process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5') + ')');
    _client = new AnthropicClient(anthropicKey);
  } else {
    console.warn('[LLMClient] No API key found. Using NoopClient (fast deterministic fallback).');
    _client = new NoopClient();
  }

  return _client;
}
