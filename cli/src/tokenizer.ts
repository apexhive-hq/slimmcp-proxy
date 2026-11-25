/**
 * Deterministic UTF-8 byte & heuristic token estimator (~4 UTF-8 bytes per token).
 * Always reports exact UTF-8 byte counts alongside heuristic token estimates.
 */
export function countUtf8Bytes(value: unknown): number {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value ?? '');
  return Buffer.byteLength(serialized, 'utf8');
}

export function estimateTokens(value: unknown): number {
  const bytes = countUtf8Bytes(value);
  if (bytes === 0) return 0;
  return Math.ceil(bytes / 4);
}

export function compactToolSummary(
  description: string | undefined,
  inputSchema: Record<string, unknown> | undefined
): { summary: string; requiredArgs: string[]; optionalArgCount: number } {
  const cleanDesc = (description ?? '')
    .replace(/\s+/g, ' ')
    .trim();
  const firstSentence = cleanDesc.split(/(?<=[.!?])\s+/)[0] ?? cleanDesc;
  const summary =
    firstSentence.length > 140
      ? `${firstSentence.slice(0, 137)}...`
      : firstSentence || 'No description provided.';

  const props =
    inputSchema && typeof inputSchema.properties === 'object' && inputSchema.properties !== null
      ? Object.keys(inputSchema.properties as Record<string, unknown>)
      : [];
  const requiredSet = new Set(
    Array.isArray(inputSchema?.required)
      ? inputSchema.required.filter((r): r is string => typeof r === 'string')
      : []
  );

  const requiredArgs = props.filter((p) => requiredSet.has(p));
  for (const r of requiredSet) {
    if (!requiredArgs.includes(r)) requiredArgs.push(r);
  }
  const optionalArgCount = Math.max(0, props.length - requiredArgs.length);

  return { summary, requiredArgs, optionalArgCount };
}
