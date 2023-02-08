/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package nl.mansoft.httpsasl;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Security;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Collection;
import nl.mansoft.security.sasl.Provider;

/**
 *
 * @author hfman
 */
public class SaslServlet extends HttpServlet {
    private static Logger LOGGER = Logger.getLogger(SaslServlet.class.getName());
    private static final String HTTP_REALM = "Java Servlet Realm";

    public static String getSaslServerFactories() {
        String mechanisms = null;
        Enumeration<SaslServerFactory> serverFactories = Sasl.getSaslServerFactories();
        while (serverFactories.hasMoreElements()) {
            SaslServerFactory serverFactory = serverFactories.nextElement();
            System.out.println(serverFactory.getClass().getName());
            for (String mechanism : serverFactory.getMechanismNames(null)) {
                mechanisms = mechanisms == null ? mechanism : mechanisms + " " + mechanism;
            }
        }
        return mechanisms;
    }

    @Override
    public void init() {
      Provider provider = new Provider();
      Security.insertProviderAt(provider, 1);
    }

    private void sendAnswer(SaslServer saslServer, HttpServletRequest request, HttpServletResponse response, String answer) throws IOException {
        try (PrintWriter out = response.getWriter()) {
            out.println(answer);
        }
    }

    private byte[] getc2s(Map<String, String> map) {
        byte[] c2s = new byte[0];
        String c2sBase64 = map.get("c2s");
        if (c2sBase64 != null) {
            LOGGER.log(Level.INFO, c2sBase64);
            c2s = Base64.getDecoder().decode(c2sBase64);
            LOGGER.log(Level.INFO, new String(c2s));
        } else {
            LOGGER.log(Level.INFO, "c2sBase64 is null");
        }
        return c2s;
    }

    private SaslServer deserializeSaslServer(String s2sBase64) {
        SaslServer saslServer = null;
        if (s2sBase64 != null) {
          try {
            LOGGER.log(Level.INFO, s2sBase64);
            byte s2sBytes[] = Base64.getDecoder().decode(s2sBase64);
            ByteArrayInputStream bais = new ByteArrayInputStream(s2sBytes);
            ObjectInputStream ois = new ObjectInputStream(bais);
            saslServer = (SaslServer) ois.readObject();
            ois.close();
          } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(SaslServlet.class.getName()).log(Level.SEVERE, null, ex);
          }
        } else {
            LOGGER.log(Level.INFO, "s2sBase64 is null");
        }
        return saslServer;
    }

    private String serializeSaslServer(SaslServer saslServer) {
      String s2sBase64 = "";
      if (saslServer != null) {
        try {
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          ObjectOutputStream oos = new ObjectOutputStream(baos);
          oos.writeObject(saslServer);
          oos.close();
          s2sBase64 = Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (IOException ex) {
          Logger.getLogger(SaslServlet.class.getName()).log(Level.SEVERE, null, ex);
        }
      }
      LOGGER.log(Level.INFO, s2sBase64);
      return s2sBase64;
    }

    private static class MyCallbackHandler implements CallbackHandler, Serializable {
      private String name;
      private String text;

      @Override
      public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        LOGGER.log(Level.INFO, "processCallbacks");
        for (Callback callback : callbacks) {
            LOGGER.log(Level.INFO, callback.getClass().getName());
            if (callback instanceof NameCallback) {
                NameCallback nameCallback = (NameCallback) callback;
                name = nameCallback.getDefaultName();
                LOGGER.log(Level.INFO, name);
                nameCallback.setName(name);
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                passwordCallback.setPassword(new char[] { '1', '2', '3', '4' });
            } else if (callback instanceof RealmCallback) {
                RealmCallback realmCallback = (RealmCallback) callback;
                text = realmCallback.getDefaultText();
                LOGGER.log(Level.INFO, text);
                realmCallback.setText(text);
            } else if (callback instanceof AuthorizeCallback) {
                ((AuthorizeCallback) callback).setAuthorized("henri".equals(name));
            }
        }
      }
    }

    private String getWwwAuthenticate(byte[] challenge, SaslServer saslServer)
    {
      String challengeBase64 = Base64.getEncoder().encodeToString(challenge);
      String s2s = serializeSaslServer(saslServer);
      String authenticate =
          "SASL s2s=\"" + s2s +
          "\",s2c=\"" + challengeBase64 + "\"";
      System.out.println(authenticate);
      return authenticate;
    }

    static public void printRequestHeaders(HttpServletRequest httpRequest) {
        Enumeration<String> headerNames = httpRequest.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();
                LOGGER.log(Level.INFO, headerName + ": " + httpRequest.getHeader(headerName));
            }
        }
    }
    static public void printResponseHeaders(HttpServletResponse httpRequest) {
        Collection<String> headerNames = httpRequest.getHeaderNames();

        if (headerNames != null) {
            for (String header: headerNames) {
                LOGGER.log(Level.INFO, header + ": " + httpRequest.getHeader(header));
            }
        }
    }
    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        printRequestHeaders(request);
        SaslServer saslServer = null;
        try {
            response.setContentType("text/plain;charset=UTF-8");
            String authorization = request.getHeader("Authorization");
            if (authorization != null) {
                Map<String, String> map = SaslParser.parse(authorization);
                if (map != null) {
                    String mechanism = map.get("mech");
                    saslServer = deserializeSaslServer(map.get("s2s"));
                    if (saslServer == null) {
                        saslServer = Sasl.createSaslServer(mechanism, "HTTP", request.getServerName(), null, new MyCallbackHandler());
                    }
                    if (saslServer != null) {
                        try {
                            byte[] c2s = getc2s(map);
                            byte[] challenge = saslServer.evaluateResponse(c2s);
                            LOGGER.log(Level.INFO, new String(challenge, "UTF-8"));
                            if (saslServer.isComplete()) {
                                LOGGER.log(Level.INFO, "saslServer.isComplete()");
                                response.setHeader("WWW-Authenticate", getWwwAuthenticate(challenge, null));
                                sendAnswer(saslServer, request, response, new String(c2s, "UTF-8"));
                            } else {
                                response.setHeader("WWW-Authenticate", getWwwAuthenticate(challenge, saslServer));
                                response.sendError(401, "Unauthorized, challenge: " + new String(challenge, "UTF-8"));
                            }
                        } catch (SaslException ex) {
                            LOGGER.log(Level.SEVERE, ex.getMessage());
                            String serverFactories = getSaslServerFactories();
                            response.setHeader("WWW-Authenticate", "SASL mech=\"" + serverFactories + "\",realm=\"" + HTTP_REALM + "\"");
                            response.sendError(401, "Unauthorized, SASL Server factories: " + serverFactories);
                        } finally {
                          saslServer.dispose();
                        }
                    } else {
                        System.out.println("saslServer is null");
                    }
                } else {
                    System.out.println("map is null");
                }
            } else {
                String serverFactories = getSaslServerFactories();
                response.setHeader("WWW-Authenticate", "SASL mech=\"" + serverFactories + "\",realm=\"" + HTTP_REALM + "\"");
                response.sendError(401, "Unauthorized, SASL Server factories: " + serverFactories);
            }
            printResponseHeaders(response);
        } catch (SaslException ex) {
            LOGGER.log(Level.SEVERE, ex.getMessage());
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>
}
