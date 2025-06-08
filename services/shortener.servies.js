import {PrismaClient} from '@prisma/client'

const prisma = new PrismaClient()

export const loadLinks = async () => {
    const shortlinks = await prisma.shortLink.findMany()
    return shortlinks;
}

export const saveLinks = async (link) => {
    return await prisma.shortLink.create({
        data : {
            url : link.url,
            shortCode : link.finalShortCode
        }
    });
}

export const getLinksByShortcode = async (shortCode) => {
    const existCheck = await prisma.shortLink.findUnique({
        where : {shortCode : shortCode}
    })
    return existCheck
}

