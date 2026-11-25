import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';

function getArg(prefix: string, fallback: string): string {
  const found = process.argv.find((a) => a.startsWith(prefix));
  return found ? found.slice(prefix.length) : fallback;
}

const serverName = getArg('--server=', 'demo');
const count = Math.max(1, Number(getArg('--count=', '20')));

const verbs = [
  'list',
  'search',
  'get',
  'create',
  'update',
  'delete',
  'export',
  'audit',
  'sync',
  'pay_x402'
];

const tools = Array.from({ length: count }, (_, idx) => {
  const verb = verbs[idx % verbs.length];
  const toolName = `${verb}_${serverName}_resource_${idx + 1}`;
  return {
    name: toolName,
    description: `Executes ${verb} operation #${idx + 1} on the ${serverName} service. Supports paginated filtering, structured metadata payloads, dry-run validation, and detailed diagnostic responses for automated engineering workflows.`,
    inputSchema: {
      type: 'object',
      properties: {
        targetId: {
          type: 'string',
          description: `Unique identifier for the ${serverName} resource item to inspect or mutate.`
        },
        query: {
          type: 'string',
          description: 'Optional filter expression or search query string.'
        },
        limit: {
          type: 'number',
          description: 'Maximum number of records to return per page (1-100).'
        },
        dryRun: {
          type: 'boolean',
          description: 'When true, validates parameters without mutating remote state.'
        },
        payload: {
          type: 'object',
          description: 'Arbitrary structured metadata or JSON body for the request.',
          properties: {
            note: { type: 'string', description: 'Human-readable audit note.' },
            tags: { type: 'array', items: { type: 'string' }, description: 'Tag labels.' }
          }
        }
      },
      required: ['targetId']
    }
  };
});

const server = new Server(
  { name: `mock-${serverName}`, version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const args = (req.params.arguments ?? {}) as Record<string, unknown>;
  // Echo args cleanly (plus optional secret fixture test if simulateOutputSecret=true)
  const extraSecret =
    args.simulateOutputSecret === true
      ? ' leaked_output=ghp_1234567890abcdefghij1234567890abcd'
      : '';
  return {
    content: [
      {
        type: 'text',
        text: `executed:${serverName}:${req.params.name}:${JSON.stringify(args)}${extraSecret}`
      }
    ]
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
