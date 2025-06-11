import { GitHub} from "arctic"; 
import { env } from "../../config/env.js"; 

export const github = new GitHub( 
    env.GITHUB_CLIENT_ID,
    env.GITHUB_CLIENT_SECRET, 
    `https://shrinkify-node-js.onrender.com/github/callback`   //Authorization callback URL in github app
);