﻿import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
} from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiTags,
  ApiOperation,
  ApiResponse,
} from "@nestjs/swagger";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { ApiErrorDto } from "../common/dto/api-error.dto";
import { RequiredRole } from "../common/decorators/required-role.decorator";
import { AuthGuard } from "../common/guards/auth.guard";
import { RoleGuard } from "../common/guards/role.guard";
import { AuthenticatedUser } from "../auth/auth.types";
import { CreateOrganizationDto } from "./dto/create-organization.dto";
import { ListOrganizationsDto } from "./dto/list-organizations.dto";
import { OrganizationResponseDto } from "./dto/organization-response.dto";
import { UpdateOrganizationDto } from "./dto/update-organization.dto";
import { Request } from "express";
import { OrganizationsService } from "./organizations.service";
import { RecentAuthGuard, RequireRecentAuth } from "../common/guards/recent-auth.guard";
import { RecentAuthService, DESTRUCTIVE_ACTIONS } from "../auth/recent-auth.service";

@ApiBearerAuth()
@ApiTags("organizations")
@Controller("organizations")
export class OrganizationsController {
  constructor(
    private readonly organizationsService: OrganizationsService,
    private readonly recentAuthService: RecentAuthService,
  ) {}

  @Post()
  @UseGuards(AuthGuard, RoleGuard)
  @RequiredRole("ADMIN")
  @ApiOperation({
    summary: "Create a new organization",
    description:
      "Admin-only endpoint to create a new organization with pending status",
  })
  @ApiResponse({
    status: 201,
    description: "Organization created successfully",
    type: OrganizationResponseDto,
  })
  @ApiResponse({
    status: 409,
    description: "Organization slug already exists",
  })
  @ApiResponse({
    status: 403,
    description: "Unauthorized - admin role required",
  })
  @ApiResponse({
    status: 401,
    description: "Session token is missing, malformed, invalid, or expired",
    type: ApiErrorDto,
  })
  createOrganization(
    @CurrentUser() user: AuthenticatedUser,
    @Body() input: CreateOrganizationDto,
  ) {
    return this.organizationsService.createOrganization(user, input);
  }

  @Get()
  @UseGuards(AuthGuard)
  @ApiOperation({
    summary: "List organizations",
    description:
      "List organizations. Admins see all, others see only their own created organizations.",
  })
  @ApiResponse({
    status: 200,
    description: "Organizations retrieved successfully",
  })
  @ApiResponse({
    status: 401,
    description: "Session token is missing, malformed, invalid, or expired",
    type: ApiErrorDto,
  })
  listOrganizations(
    @CurrentUser() user: AuthenticatedUser,
    @Query() query: ListOrganizationsDto,
  ) {
    return this.organizationsService.listOrganizations(user, query);
  }

  @Get(":id")
  @UseGuards(AuthGuard)
  @ApiOperation({
    summary: "Get organization details",
    description:
      "Retrieve full details of an organization including issuer count",
  })
  @ApiResponse({
    status: 200,
    description: "Organization retrieved successfully",
    type: OrganizationResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: "Organization not found",
  })
  @ApiResponse({
    status: 401,
    description: "Session token is missing, malformed, invalid, or expired",
    type: ApiErrorDto,
  })
  getOrganization(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") organizationId: string,
  ) {
    return this.organizationsService.getOrganization(user, organizationId);
  }

  @Patch(":id")
  @UseGuards(AuthGuard, RoleGuard)
  @ApiOperation({
    summary: "Update organization",
    description:
      "Update organization name and/or website. Only creator or admin can update.",
  })
  @ApiResponse({
    status: 200,
    description: "Organization updated successfully",
    type: OrganizationResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: "Organization not found",
  })
  @ApiResponse({
    status: 403,
    description: "Unauthorized - not creator or admin",
  })
  @ApiResponse({
    status: 401,
    description: "Session token is missing, malformed, invalid, or expired",
    type: ApiErrorDto,
  })
  updateOrganization(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") organizationId: string,
    @Body() input: UpdateOrganizationDto,
  ) {
    return this.organizationsService.updateOrganization(
      user,
      organizationId,
      input,
    );
  }

  @Delete(":id")
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(AuthGuard, RoleGuard, RecentAuthGuard)
  @RequireRecentAuth(DESTRUCTIVE_ACTIONS.ORG_DELETE)
  @RequiredRole("ADMIN")
  @ApiOperation({
    summary: "Delete an organization (destructive — requires recent-auth)",
    description:
      "Permanently deletes an organization. Requires a recent-auth assertion token " +
      "in the X-Recent-Auth header (obtained from POST /auth/assert).",
  })
  @ApiResponse({ status: HttpStatus.NO_CONTENT, description: "Organization deleted." })
  @ApiResponse({ status: 401, description: "Session token invalid.", type: ApiErrorDto })
  @ApiResponse({ status: 403, description: "Not authorized or recent-auth missing.", type: ApiErrorDto })
  async deleteOrganization(
    @CurrentUser() user: AuthenticatedUser,
    @Param("id") organizationId: string,
    @Req() req: Request,
  ): Promise<void> {
    const assertionToken = String(req.headers["x-recent-auth"] ?? "");
    const origin = String(req.headers["origin"] ?? "null");
    // Consume the assertion — this is the point of no return.
    await this.recentAuthService.consume({
      token: assertionToken,
      action: DESTRUCTIVE_ACTIONS.ORG_DELETE,
      resourceId: organizationId,
      origin,
    });
    await this.organizationsService.deleteOrganization(user, organizationId);
  }
}
