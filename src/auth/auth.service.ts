import { HttpCode, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from 'generated/prisma';
import { LoginUserDto, RegisterUserDto } from './dto';

import * as bcrypt from 'bcrypt';
import { STATUS_CODES } from 'http';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit{

    private readonly logger = new Logger('AuthService');

    constructor(
        private readonly jwtService : JwtService

    ){
        super();
    }

    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDB connected');
    }


    private async signJWT(payload : JwtPayload){

        return this.jwtService.sign(payload);

    }

    async verifyToken(token : string){
        try {
            console.log('ingreso aqui')
            const {sub, iat, exp, ...user} = this.jwtService.verify(token, {
                secret: envs.jwtSecret,
            });

            

            return {
                user : user,
                token : await this.signJWT(user)
            }

        } catch (error) {
            throw new RpcException({
                status: 401,
                message: 'Invalid Token',
            })
        }
    }

    async registerUser(registerUserDto : RegisterUserDto) {

        const {email, name, password} = registerUserDto;

        try {

            const user = await this.user.findUnique({
                where: {email}
            });

            if(user){
                throw new RpcException({
                    status: 400,
                    message: 'User already exists',
                })
            } 
            
            const newUser = await this.user.create({
                data: {
                    email,
                    name,
                    password : bcrypt.hashSync(password, 10),
                }
            });


            const {password : _, ...rest} = newUser
            return {
                user : rest,
                token : await this.signJWT(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message,
            })
        }
    }


    async loginUser(loginUserDto : LoginUserDto) {

        const {email, password} = loginUserDto;

        try {

            const user = await this.user.findUnique({
                where: {email}
            });

            if(!user){
                throw new RpcException({
                    status: 400,
                    message: 'Invalid Credentials',
                })
            } 
            
            const isPasswordValid = await bcrypt.compare(password, user.password);

            if(!isPasswordValid){
                throw new RpcException({
                    status: 400,
                    message: 'Invalid Credentials',
                })
            }


            const {password : _, ...rest} = user
            return {
                user : rest,
                token : await this.signJWT(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message,
            })
        }
    }

}
