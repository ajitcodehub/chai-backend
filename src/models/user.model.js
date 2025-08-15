import mongoose, {schema} from "mongoose";
import { JsonWebTokenError } from "jsonwebtoken";
import bcrypt from "bcryptjs";  

const userSchema = new Schema(
    {
        userName:{
            type: String,
            required: true,
            trim: true,
            unique: true,
            lowercase: true,
            index: true,

        },
        email:{
            type: String,
            required: true,
            trim: true,
            unique: true,
            lowercase: true,
        },
        fullName:{
            type: String,
            required: true,
            trim: true,
            index: true,

        },
        avata:{
            type: String,
            required: true,

        },
        coverImage:{
            type: String,
        },
        watchHistory:[
          {  type: schema.types.objectid,
            ref: "Video"
          }
        ],
        password:{
            type: String,
            required: [true, "Password is required"],
            trim: true,
            minlength: 6,
            select: false
        },
        refreshToken:{
            type: String,
        }

    },
    { timestamps: true }
)

userSchema.pre("save", async function(next) {
    if (!this.isModified("password")) return next();
    try {
        this.password = await bcrypt.hash(this.password, 10);
        next();
    } catch (error) {
        next(error);
    }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw new JsonWebTokenError("Password comparison failed");
    }
};

userSchema.methods.generateAccessToken = function() {
    return jwt.sign({ 
        id: this._id,
        email: this.email,
        userName: this.userName ,
        fullName: this.fullName

     }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRY
    });
};

userSchema.methods.generateRefreshToken = function() {
   return jwt.sign({ 
        id: this._id

     }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRY
    });
};

export const User = mongoose.model("User",userSchema)