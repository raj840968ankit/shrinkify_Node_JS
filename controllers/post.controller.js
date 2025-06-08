import crypto from 'crypto'
import { saveLinks, loadLinks, getLinksByShortcode, findShortLinkById, updateShortLinkById, deleteShortCodeById } from '../models/data.model.js';
import z from 'zod';
import { shortenerSchema } from '../validators/shortener.validator.js';

const postShortener = async (req, res) => {
    try {
        if(!req.user){
            return res.redirect('/auth/login');
        }
        const {data, error} = shortenerSchema.safeParse(req.body);
        //console.log("Data : ",data);
        //console.log("Error : ",error);
        
        if(error){
            const errors = error.errors[0].message;
            req.flash("errors", errors);
            return res.redirect('/')
        }
        const {url, shortCode} =  data
        
        // const links = await loadLinks()
        const finalShortCode = shortCode || crypto.randomBytes(4).toString("hex")
        //console.log(links);
        
        const [link] = await getLinksByShortcode(finalShortCode)
        //console.log(link);
        
        
        //checking in file if shortCode exists
        // if(links[finalShortCode]){
        //     return res.status(400).send("Short code already exists, Please choose another")
        // }

        // Check if shortCode already exists
        // for (const link of links) {
        //     if (link.shortCode === finalShortCode) {
        //         return res.status(400).send("Short code already exists, Please choose another");
        //     }
        // }

        //if not exists then give value of url to finalShortCode
        // links[finalShortCode] = url
        // await saveLinks(links)

        // await saveLinks({finalShortCode, url }) 
        if(link){
            req.flash("errors", "URL already exists, Please choose another")
            return res.redirect('/');
        }

        //!after making relation between table
        await saveLinks({finalShortCode, url, userId : req.user.id}) 

        return res.redirect('/');
    } catch (error) {
        console.log(error);
    }
}

const getReport = (req,res) => {
    const student = [{name : 'Ankit', grade : "5th", favoriteSubject : 'Science'},
        {name : 'Ishita', grade : "5th", favoriteSubject : 'History'},
        {name : 'Rohan', grade : "9th", favoriteSubject : 'Biology'},
        {name : 'Kabir', grade : "8th", favoriteSubject : 'Chemistry'},
        {name : 'Gaurav', grade : "10th", favoriteSubject : 'Physics'}
    ];
    return res.render("report", { student })
}

const getShortenerPage = async (req, res) => {
  try {
    if(!req.user){
        return res.redirect('/auth/login');
    }
    // const links = await loadLinks();

    //!after making relation between table
    const links = await loadLinks(req.user.id);

    //!getting cookie detail (complex)
    // let isLoggedIn = req.headers.cookie;
    // isLoggedIn = Boolean(isLoggedIn?.split('=')[1])   //extracting 'isLoggedIn=true' value to 'true' only
    // console.log("Logged in value -> ",isLoggedIn);

    //!getting cookie detail via cookieParser
    // let isLoggedIn = req.cookies.isLoggedIn
    //console.log(isLoggedIn);
    // return res.render('index', { links, req, isLoggedIn });  // passing req so you can use req.headers.host in ejs

    //! we are trying to send user details after verifying JWT token and using middleware in app.js
    return res.render('index', { links, req, errors : req.flash('errors'), success : req.flash('success')});
  } catch (error) {
    console.error("Error in getShortenerPage:", error);
    return res.status(500).send("Internal server error");
  }
}

const getShortLink = async (req, res) => {
    try {
        const { shortCode } = req.params;
        const [link] = await getLinksByShortcode(shortCode);

        if (!link) {
            // don't log anything here if you don’t want tons of "undefined"
            return res.status(404).send('Not found');
        }

        console.log('Found link:', link);
        return res.redirect(link.url);
    } catch (error) {
        console.log(error);
        return res.status(500).send("Internal server error")
    }
}


const getShortenerEditPage = async (req, res) => {
    if (!req.user) return res.redirect("/login"); 
    // const id = req.params; 
    const { data: id, error} = z.coerce.number().int().safeParse(req.params.id); 

    if (error) return res.redirect("/404"); 
    
    try { 
        const shortLink = await findShortLinkById(id); 
        if(!shortLink) {
            return res.redirect('/404')
        }

        res.render('edit-shortlink', {
            id : shortLink.id,
            url : shortLink.url,
            shortCode : shortLink.shortCode,
            errors : req.flash('errors'),
            success : req.flash('success') 
        })
    } catch (err) { 
        console.error(err); 
        return res.status(500).send("Internal server error"); 
    }
}

const postShortenerEdit = async (req, res) => {
    if(!req.user){
            return res.redirect('/auth/login');
    }
    try{
        const {data, error} = shortenerSchema.safeParse(req.body);
        //console.log("Data : ",data);
        //console.log("Error : ",error);
        
        if(error){
            const errors = error.errors[0].message;
            req.flash("errors", errors);
            return res.redirect(`/edit/${req.params.id}`)
        }
        const {url, shortCode} =  data
        const [link] = await getLinksByShortcode(shortCode)

        //console.log(link);
        if(link){
            req.flash("errors", "ShortCode already exists, Please choose another")
            return res.redirect(`/edit/${req.params.id}`);
        }
        const updatedData = await updateShortLinkById({id : req.params.id, url, shortCode})
        if(updatedData.affectedRows > 0){
            req.flash('success', 'shortcode is updated')
            return res.redirect(`/`)
        }
        return res.redirect('/')
    }catch(error){
        console.error("Shortener Edit :",error)
        res.status(400).send("Shortener Edit : Bad Request")
    }
        
}

const postShortenerDelete = async (req, res) => {
    if(!req.user){
        return res.redirect('/auth/login');
    }
    try {
        const { data: id, error} = z.coerce.number().int().safeParse(req.params.id); 

        if (error) return res.redirect("/404"); 

        await deleteShortCodeById(id)
        return res.redirect("/")
    } catch (error) {
        console.error("Shortener Delete :",error)
        res.status(400).send("Shortener Delete : Bad Request")
    }
}

//exporting this function to use in shortener.routes.js
export { postShortener, getReport, getShortenerPage, getShortLink, getShortenerEditPage, postShortenerEdit, postShortenerDelete };