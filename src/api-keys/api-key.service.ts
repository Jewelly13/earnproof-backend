import {
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from "@nestjs/common";
import { ApiKeyScope, ResourceStatus } from "@prisma/client";
import { randomBytes, timingSafeEqual } from "crypto";
import { sha256 } from "../common/crypto/hash";
import { PrismaService } from "../database/prisma.service";
import { ApiKeyUsageService } from "./api-key-usage.service";

/**
 * API Key Service - Secure credential management for machine-to-machine integrations.
 *
 * See original file for full design rationale. Changes in this version:
 * - Injects ApiKeyUsageService to call freezeOnRevocation() during revokeKey().
 * - recordKeyUsage() is kept for backward compatibility; new code should use
 *   ApiKeyUsageService.recordUsage() directly (via the guard).
 */
@Injectable()
export class ApiKeyService {
  private readonly logger = new Logger(ApiKeyService.name);
  private readonly KEY_BYTES = 32;

  constructor(
    private readonly prisma: PrismaService,
    private readonly apiKeyUsageService: ApiKeyUsageService,
  ) {}

  generateSecret(): { secret: string; prefix: string } {
    const randomBytes32 = randomBytes(this.KEY_BYTES);
    const secret = randomBytes32.toString("base64url");
    const prefix = secret.substring(0, 8);
    return { secret, prefix };
  }

  hashSecret(secret: string): string {
    return sha256(secret);
  }

  verifySecret(secret: string, storedHash: string): boolean {
    const computedHash = this.hashSecret(secret);
    const isValidFormat = /^[a-f0-9]{64}$/i.test(storedHash);
    const hashBufferToCompare = isValidFormat
      ? Buffer.from(storedHash, "hex")
      : Buffer.alloc(32);
    try {
      return timingSafeEqual(Buffer.from(computedHash, "hex"), hashBufferToCompare);
    } catch {
      return false;
    }
  }

  async lookupAndVerifyKey(prefix: string, secret: string, organizationId: string) {
    const apiKey = await this.prisma.apiKey.findFirst({
      where: {
        prefix,
        organizationId,
        status: ResourceStatus.ACTIVE,
        OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
      },
      include: {
        scopeAssignments: { select: { scope: true } },
        organization: { select: { id: true, slug: true } },
      },
    });

    if (!apiKey) return null;
    const isValid = this.verifySecret(secret, apiKey.keyHash);
    if (!isValid) return null;
    return apiKey;
  }

  async createKey(input: {
    organizationId: string;
    createdBy: string;
    name: string;
    scopes?: ApiKeyScope[];
    expiresAt?: Date;
  }) {
    const { secret, prefix } = this.generateSecret();
    const keyHash = this.hashSecret(secret);

    const apiKey = await this.prisma.apiKey.create({
      data: {
        organizationId: input.organizationId,
        createdById: input.createdBy,
        name: input.name,
        prefix,
        keyHash,
        expiresAt: input.expiresAt,
        scopeAssignments: input.scopes
          ? { createMany: { data: input.scopes.map((scope) => ({ scope })) } }
          : undefined,
      },
      include: { scopeAssignments: { select: { scope: true } } },
    });

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: input.createdBy,
        action: "api_key.created",
        resourceType: "api_key",
        resourceId: apiKey.id,
        metadata: {
          prefix: apiKey.prefix,
          name: apiKey.name,
          organizationId: apiKey.organizationId,
          scopes: apiKey.scopeAssignments.map((sa) => sa.scope),
          expiresAt: apiKey.expiresAt?.toISOString(),
        },
      },
    });

    return {
      secret,
      apiKey: {
        id: apiKey.id,
        prefix: apiKey.prefix,
        name: apiKey.name,
        status: apiKey.status,
        scopes: apiKey.scopeAssignments.map((sa) => sa.scope),
        createdAt: apiKey.createdAt,
        expiresAt: apiKey.expiresAt,
      },
    };
  }

  async rotateKey(keyId: string, organizationId: string, actorId?: string) {
    const { secret, prefix } = this.generateSecret();
    const keyHash = this.hashSecret(secret);

    const apiKey = await this.prisma.apiKey.update({
      where: { id: keyId, organizationId },
      data: { prefix, keyHash, rotatedAt: new Date() },
      include: { scopeAssignments: { select: { scope: true } } },
    });

    if (apiKey.organizationId !== organizationId) {
      throw new ForbiddenException("Key does not belong to this organization");
    }

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: actorId ?? null,
        action: "api_key.rotated",
        resourceType: "api_key",
        resourceId: apiKey.id,
        metadata: {
          prefix: apiKey.prefix,
          name: apiKey.name,
          organizationId: apiKey.organizationId,
          rotatedAt: apiKey.rotatedAt?.toISOString(),
        },
      },
    });

    return {
      secret,
      apiKey: {
        id: apiKey.id,
        prefix: apiKey.prefix,
        name: apiKey.name,
        status: apiKey.status,
        scopes: apiKey.scopeAssignments.map((sa) => sa.scope),
        rotatedAt: apiKey.rotatedAt,
      },
    };
  }

  async revokeKey(keyId: string, organizationId: string, actorId?: string) {
    const apiKey = await this.prisma.apiKey.findFirst({
      where: { id: keyId, organizationId },
      select: { organizationId: true, prefix: true, name: true },
    });

    if (!apiKey) throw new NotFoundException("Key not found");

    await this.prisma.apiKey.update({
      where: { id: keyId, organizationId },
      data: { status: ResourceStatus.REVOKED, revokedAt: new Date() },
    });

    // Freeze usage summaries so the final state is auditable.
    // Fire-and-forget — revocation must not be blocked by summary writes.
    void this.apiKeyUsageService.freezeOnRevocation(keyId);

    await this.prisma.auditLog.create({
      data: {
        actorType: "user",
        actorId: actorId ?? null,
        action: "api_key.revoked",
        resourceType: "api_key",
        resourceId: keyId,
        metadata: {
          prefix: apiKey.prefix,
          name: apiKey.name,
          organizationId: apiKey.organizationId,
          revokedAt: new Date().toISOString(),
        },
      },
    });
  }

  async listKeysForOrganization(organizationId: string) {
    return this.prisma.apiKey.findMany({
      where: { organizationId },
      select: {
        id: true,
        prefix: true,
        name: true,
        status: true,
        scopeAssignments: { select: { scope: true } },
        createdAt: true,
        rotatedAt: true,
        revokedAt: true,
        expiresAt: true,
        lastUsedAt: true,
      },
      orderBy: { createdAt: "desc" },
    });
  }

  /**
   * Kept for backward compatibility with existing tests.
   * New code should prefer ApiKeyUsageService.recordUsage() directly.
   */
  async recordKeyUsage(keyId: string, organizationId?: string) {
    try {
      const updated = await this.prisma.apiKey.update({
        where: { id: keyId },
        data: { lastUsedAt: new Date() },
        select: { prefix: true, name: true, organizationId: true },
      });

      if (organizationId && organizationId === updated.organizationId) {
        await this.prisma.auditLog.create({
          data: {
            actorType: "api_key",
            actorId: keyId,
            action: "api_key.authenticated",
            resourceType: "api_key",
            resourceId: keyId,
            metadata: {
              prefix: updated.prefix,
              organizationId: updated.organizationId,
              timestamp: new Date().toISOString(),
            },
          },
        });
      }
    } catch {
      this.logger.warn(`Failed to record API key usage for ${keyId}`);
    }
  }
}