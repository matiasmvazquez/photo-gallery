// netlify/functions/google-drive-proxy.js
// Función serverless para manejar requests a Google Drive API de forma segura

const { google } = require('googleapis');

exports.handler = async (event, context) => {
  // Headers CORS para permitir requests desde el frontend
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Manejar preflight OPTIONS request
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  try {
    // Obtener credenciales de variables de entorno
    const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
    const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
    const API_KEY = process.env.GOOGLE_API_KEY;
    
    if (!CLIENT_ID || !CLIENT_SECRET || !API_KEY) {
      throw new Error('Credenciales de Google no configuradas en variables de entorno');
    }

    // Parsear el body de la request
    let requestBody;
    try {
      requestBody = JSON.parse(event.body || '{}');
    } catch (parseError) {
      throw new Error('JSON inválido en el body de la request');
    }

    const { action, folderId, accessToken } = requestBody;

    if (!accessToken) {
      throw new Error('Access token requerido');
    }

    // Configurar cliente OAuth2 de Google
    const oauth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET);
    oauth2Client.setCredentials({ access_token: accessToken });

    // Inicializar Google Drive API
    const drive = google.drive({ version: 'v3', auth: oauth2Client });

    // Manejar diferentes acciones
    switch (action) {
      case 'listFolders':
        // Obtener lista de carpetas permitidas desde variables de entorno
        let allowedFolders = [];
        try {
          allowedFolders = JSON.parse(process.env.ALLOWED_FOLDERS || '[]');
        } catch (error) {
          console.error('Error parseando ALLOWED_FOLDERS:', error);
          allowedFolders = [];
        }

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({ 
            success: true,
            folders: allowedFolders 
          })
        };

      case 'listFiles':
        if (!folderId) {
          throw new Error('folderId es requerido para listFiles');
        }

        // Verificar que el folderId está en la lista de carpetas permitidas
        const allowedFolderIds = JSON.parse(process.env.ALLOWED_FOLDERS || '[]')
          .map(folder => folder.id);
        
        if (!allowedFolderIds.includes(folderId)) {
          throw new Error('Acceso no autorizado a esta carpeta');
        }

        // Obtener archivos de la carpeta
        const filesResponse = await drive.files.list({
          q: `'${folderId}' in parents and mimeType contains 'image/' and trashed=false`,
          fields: 'nextPageToken, files(id, name, mimeType, thumbnailLink, size, createdTime)',
          pageSize: 100,
          orderBy: 'createdTime desc'
        });

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({ 
            success: true,
            files: filesResponse.data.files || [],
            totalFiles: filesResponse.data.files?.length || 0
          })
        };

      case 'getDownloadUrl':
        const fileId = requestBody.fileId || event.queryStringParameters?.fileId;
        
        if (!fileId) {
          throw new Error('fileId es requerido para getDownloadUrl');
        }

        // Verificar que el archivo existe y obtener metadata
        const fileResponse = await drive.files.get({
          fileId: fileId,
          fields: 'id, name, mimeType, size, parents'
        });

        // Verificar que el archivo está en una carpeta permitida
        const fileParents = fileResponse.data.parents || [];
        const allowedIds = JSON.parse(process.env.ALLOWED_FOLDERS || '[]')
          .map(folder => folder.id);
        
        const hasPermission = fileParents.some(parentId => allowedIds.includes(parentId));
        
        if (!hasPermission) {
          throw new Error('No tienes permisos para descargar este archivo');
        }

        // Generar URL de descarga directa
        const downloadUrl = `https://drive.google.com/uc?export=download&id=${fileId}`;

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({
            success: true,
            downloadUrl: downloadUrl,
            fileName: fileResponse.data.name,
            fileSize: fileResponse.data.size,
            mimeType: fileResponse.data.mimeType
          })
        };

      case 'getFileMetadata':
        const metadataFileId = requestBody.fileId;
        
        if (!metadataFileId) {
          throw new Error('fileId es requerido para getFileMetadata');
        }

        const metadataResponse = await drive.files.get({
          fileId: metadataFileId,
          fields: 'id, name, mimeType, size, createdTime, modifiedTime, imageMediaMetadata'
        });

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({
            success: true,
            metadata: metadataResponse.data
          })
        };

      default:
        throw new Error(`Acción no válida: ${action}`);
    }

  } catch (error) {
    console.error('Error en google-drive-proxy:', error);
    
    // Determinar el código de status apropiado
    let statusCode = 500;
    if (error.message.includes('no autorizado') || error.message.includes('permisos')) {
      statusCode = 403;
    } else if (error.message.includes('requerido') || error.message.includes('inválido')) {
      statusCode = 400;
    } else if (error.code === 404) {
      statusCode = 404;
    }

    return {
      statusCode,
      headers,
      body: JSON.stringify({ 
        success: false,
        error: error.message || 'Error interno del servidor',
        timestamp: new Date().toISOString()
      })
    };
  }
};