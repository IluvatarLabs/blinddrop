import Anthropic from '@anthropic-ai/sdk';

const model = process.argv[2];
if (!model) throw new Error('Usage: node anthropic.mjs MODEL [PROMPT]');
const client = new Anthropic({ maxRetries: 0 });
const stream = await client.messages.create({
  model,
  max_tokens: 256,
  messages: [{ role: 'user', content: process.argv[3] ?? 'Say hello in one sentence.' }],
  stream: true,
});
for await (const event of stream) {
  if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
    process.stdout.write(event.delta.text);
  }
}
process.stdout.write('\n');
