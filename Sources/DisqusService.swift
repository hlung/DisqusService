//
//  DisqusService.swift
//  Subspedia
//
//  Created by Matteo Riva on 05/09/16.
//  Copyright © 2016 Matteo Riva. All rights reserved.
//

import Foundation
import SafariServices

public extension Notification.Name {
    static let DisqusServiceSafariAuthDidClose = Notification.Name("DisqusServiceSafariAuthDidClose")
}

public enum HTTPMethod: String {
    case get = "GET"
    case post = "POST"
    case delete = "DELETE"
    case patch = "PATCH"
    case put = "PUT"
}

public class DisqusService: NSObject, SFSafariViewControllerDelegate {
    
    public typealias disqusAuthCompletion = (Bool) -> Void
    public typealias disqusAPICompletion = ([AnyHashable : Any]?, Bool) -> Void
    
    public static let shared = DisqusService()
    
    private let authURL = "https://disqus.com/api/oauth/2.0/"
    private let baseURL = "https://disqus.com/api/3.0/"
    
    private var secretKey: String!
    private var publicKey: String!
    private var redirectURI: String!
    
    private var loggedUser: DisqusUser? {
        didSet {
            if loggedUser != nil {
                let data = NSKeyedArchiver.archivedData(withRootObject: loggedUser!)
                UserDefaults.standard.set(data, forKey: "disqusLoggedUser")
            } else {
                UserDefaults.standard.removeObject(forKey: "disqusLoggedUser")
            }
        }
    }
    
    public var loggedUserID: String? {
        get { return loggedUser?.userID }
    }
    
    public var isUserAuthenticated: Bool {
        get { return loggedUser != nil }
    }
    
    //MARK: - Init
    
    private override init() {
        if let data = UserDefaults.standard.data(forKey: "disqusLoggedUser") {
            loggedUser = NSKeyedUnarchiver.unarchiveObject(with: data) as? DisqusUser
        }
        super.init()
    }
    
    public func set(publicKey: String, secretKey: String, redirectURI: String) {
        self.publicKey = publicKey
        self.secretKey = secretKey
        self.redirectURI = redirectURI
        loggedUser?.refreshToken(publicKey: publicKey, secretKey: secretKey) {[unowned self] (success) in
            if success {
                let data = NSKeyedArchiver.archivedData(withRootObject: self.loggedUser!)
                UserDefaults.standard.set(data, forKey: "disqusLoggedUser")
            }
        }
    }
    
    //MARK: - Auth
    
    public func authenticate(viewController: UIViewController, completionHandler: @escaping disqusAuthCompletion) {
        
        var urlString = "authorize/"
        urlString += "?client_id=\(publicKey!)"
        urlString += "&scope=read,write"
        urlString += "&response_type=code"
        urlString += "&redirect_uri=\(redirectURI!)"
        
        let url = URL(string: authURL + urlString)!
        
        if #available(iOS 9.0, *) {
            let safariVC = SFSafariViewController(url: url)
            safariVC.delegate = self
            viewController.present(safariVC, animated: true, completion: nil)
            NotificationCenter.default.addObserver(forName: .DisqusServiceSafariAuthDidClose,
                                                   object: nil, queue: .main ) {[unowned self] (notif) in
                                                    safariVC.dismiss(animated: true, completion: nil)
                                                    let tmpCode = (notif.object as! URL).query!.replacingOccurrences(of: "code=", with: "")
                                                    let url2 = URL(string: self.authURL + "access_token/")!
                                                    let params = ["grant_type" : "authorization_code",
                                                                  "client_id" : self.publicKey!,
                                                                  "client_secret" : self.secretKey!,
                                                                  "redirect_uri" : self.redirectURI!.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!,
                                                                  "code" : tmpCode]
                                                    
                                                    self.performDisqusDictionaryTask(url: url2, method: .post, params: params) { [unowned self] (json, success) in
                                                        if let json = json {
                                                            self.loggedUser = DisqusUser(json: json)
                                                        }
                                                        completionHandler(success)
                                                    }
            }
        } else {
            let nav = DisqusAuthViewController()
            nav.url = url
            nav.callback = { (tmpCode) in
                let url2 = URL(string: self.authURL + "access_token/")!
                let params = ["grant_type" : "authorization_code",
                              "client_id" : self.publicKey!,
                              "client_secret" : self.secretKey!,
                              "redirect_uri" : self.redirectURI!.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!,
                              "code" : tmpCode]

                self.performDisqusDictionaryTask(url: url2, method: .post, params: params) { [unowned self] (json, success) in
                    if let json = json {
                        self.loggedUser = DisqusUser(json: json)
                    }
                    completionHandler(success)
                }
            }
            let navVC = UINavigationController(rootViewController: nav)
            viewController.present(navVC, animated: true, completion: nil)
        }
    }
    
    public func logout() {
        loggedUser = nil
    }
    
    //MARK: - Api call
    
    public func performGETRequest(api: String, authRequired: Bool = false, params: [AnyHashable : Any], completionHandler: @escaping disqusAPICompletion) {
        let url = URL(string: baseURL + api + ".json")!
        performDisqusDictionaryTask(url: url, authRequired: authRequired, method: .get, params: params, completionHandler: completionHandler)
    }
    
    public func performPOSTRequest(api: String, authRequired: Bool = false, params: [AnyHashable : Any], completionHandler: @escaping disqusAPICompletion) {
        let url = URL(string: baseURL + api + ".json")!
        performDisqusDictionaryTask(url: url, authRequired: authRequired, method: .post, params: params,completionHandler: completionHandler)
    }

    private func performDisqusDictionaryTask(url: URL, authRequired: Bool = false, method: HTTPMethod, params: [AnyHashable : Any], completionHandler: @escaping disqusAPICompletion) {
        performDisqusTask(url: url, authRequired: authRequired, method: method, params: params, completionHandler: { (data, error) in
            var json: Any? = nil
            if data != nil {
                json = try? JSONSerialization.jsonObject(with: data!, options: [])
            }
            let errorCond = error == nil && ((json as? [AnyHashable : Any])?["code"] as? Int) == 0
            completionHandler(json as? [AnyHashable : Any], errorCond)
        })
    }

    public func performDisqusTask(url: URL, authRequired: Bool = false, method: HTTPMethod, params: [AnyHashable : Any], completionHandler: @escaping DataCompletion) {
        var params = params
        params["api_key"] = publicKey!
        params["api_secret"] = secretKey!

        if let token = loggedUser?.accessToken {
            if authRequired {
                params["access_token"] = token
            }
        }
        performDataTask(url: url, method: method, params: params, completionHandler: completionHandler)
    }
    
    //MARK: - General

    public typealias DataCompletion = (Data?, Error?) -> Void

    /// Designated network request performer
    func performDataTask(url: URL, method: HTTPMethod, params: [AnyHashable : Any], completionHandler: @escaping DataCompletion) {
        var request: URLRequest

        switch method {
        case .post:
            request = URLRequest(url: url)
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            var paramString = ""
            for (key,value) in params {
                paramString += "\(key)=\(value)&"
            }
            paramString.removeLast()
            request.httpBody = paramString.data(using: String.Encoding.utf8)!
        default:
            var paramString = "?"
            for (key,value) in params {
                paramString += "\(key)=\(value)&"
            }
            paramString.removeLast()
            let finalURL = URL(string: url.absoluteString + paramString)!
            request = URLRequest(url: finalURL)
        }

        request.httpMethod = method.rawValue
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        URLSession.shared.dataTask(with: request, completionHandler: { (data, _, error) in
            completionHandler(data, error)
        }).resume()
    }
    
    //MARK: - SFSafariViewControllerDelegate
    
    @available(iOS 9.0, *)
    public func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
        
    }

}
