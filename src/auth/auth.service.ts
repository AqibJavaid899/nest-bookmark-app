import { Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

  signup() {
    return { message: "I am signing up." };
  }

  signin() {
    return { message: "I am signing in." };
  }
}
