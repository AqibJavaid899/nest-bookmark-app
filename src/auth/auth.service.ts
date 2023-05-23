import { ForbiddenException, Injectable } from "@nestjs/common";
import * as argon from "argon2";

import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto";

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    // create the hash password
    const hashedPassword = await argon.hash(dto.password);

    try {
      // save the user in the db
      const savedUser = await this.prisma.user.create({
        data: {
          email: dto.email,
          password: hashedPassword,
        },
      });

      // deleting the hashedPassword from the saved user object
      const { password, ...user } = savedUser;

      // return the saved user
      return user;
    } catch (error) {
      if (error.code === "P2002") {
        throw new ForbiddenException(
          "Credentials already taken by another user."
        );
      }

      throw error;
    }
  }

  async signin(dto: AuthDto) {
    // Find the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // Throw error if the user does not exist
    if (!user)
      throw new ForbiddenException("Provided credentials are incorrect.");

    // Compare the password
    const isMatched = await argon.verify(user.password, dto.password);

    // Throw error if password does not matched
    if (!isMatched)
      throw new ForbiddenException("Provided credentials are incorrect.");

    // Return user without hash password
    const { password, ...userObject } = user;
    return userObject;
  }
}
