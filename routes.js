import {Router} from 'express';
import {body, header } from 'express-validator';
import controller, {validate, fetchUserByEmailOrID } from './controller.js';

const routes = Router({ strict: true });

const tokenValidation = (isRefresh = false)=>{
    let refreshText = isRefresh ? 'Refresh': 'Authorization';

    return[
        header('Authorization',`Please provide your ${refreshText} token`)
        .exists()
        .not()
        .isEmpty()
        .custom((value, {req})=>{
            if(!value.startsWith('Bearer')||value.split('')[1]){
                throw new Error(`Invalid ${refreshText} token`);
            }
            if(isRefresh){
                req.headers.refresh_token = value.split('')[1];
                return true;
            }
            req.headers.access.token = value.split('')[1];
            return true;
        }),
    ];
};

//registration:
routes.post(
    '/register',
    [
        body('name')
        .trim()
        .not()
        .isEmpty()
        .withMessage('name cannot be empty')
        .isLength({ min:3 })
        .withMessage('name should have at least 3 characters')
        .escape(),
        body('email','Invalid email')
        .trim()
        .isEmail()
        .custom(async(email)=>{
            const isExist = await fetchUserByEmailOrID(email);
            if(isExist.length)
            throw new Error('A user with this email is already in the database');
        return true;
        }),
        body('password')
        .trim()
        .isLength({ min:4 })
        .withMessage('Password should have more than 4 characters.'),
    ],
    validate,
    controller.register
    );

    routes.post(
        '/signin',
        [
            body('email', 'Invalid email')
            .trim()
            .isEmail()
            .custom(async(email,{req})=>{
                const isExist = await fetchUserByEmailOrID(email);
                if(isExist.length===0)
                throw new Error('Your email is not found. Register');
            req.body.user=isExist[0];
            return true;
            }),
            body('password',"Wrong password").trim().isLength({ min:4}),
],
validate,
controller.signin
);

routes.get('/profile', tokenValidation(), validate, controller.getUser);

routes.get(
    '/refresh',
    tokenValidation(true),
    validate,
    controller.refreshToken,
);

export default routes;
