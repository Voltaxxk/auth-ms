
import 'dotenv/config';
import * as joi from 'joi';


interface EnvvVars {

    PORT : number
    NATS_SERVERS : string
    JWT_SECRET : string

}

const envSchema = joi.object({
    PORT: joi.number().required(),
    NATS_SERVERS: joi.string().required(),
    JWT_SECRET : joi.string().required()
})
.unknown(true)

const {error, value} = envSchema.validate(process.env);

if(error){
    throw new Error(`Config Error: ${error.message}`)
}

const envVars : EnvvVars = value
export const envs = {
    port : envVars.PORT,
    natsServers : envVars.NATS_SERVERS.split(','),
    jwtSecret : envVars.JWT_SECRET
}